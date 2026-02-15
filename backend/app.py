"""
Quantum-Secure Vault - Backend API
===================================
Flask REST API for web-based credential vault
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import json
import base64
import secrets

# Import our vault logic
from vault_core import QuantumSecureVault

app = Flask(__name__, static_folder='frontend/build', static_url_path='')
CORS(app)

# Database configuration
# For production: use PostgreSQL
# postgres://username:password@localhost/dbname
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///vault_production.db')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

db = SQLAlchemy(app)

# Database Models
class VaultCredential(db.Model):
    """Database model for stored credentials"""
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    encrypted_data = db.Column(db.Text, nullable=False)
    ml_kem_ciphertext = db.Column(db.Text, nullable=False)
    shares_data = db.Column(db.Text, nullable=False)  # JSON array of shares
    salt = db.Column(db.String(255), nullable=False)
    nonce = db.Column(db.String(255), nullable=False)
    threshold = db.Column(db.Integer, nullable=False)
    total_shares = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    metadata_json = db.Column(db.Text)  # JSON metadata
    access_count = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'credential_id': self.credential_id,
            'threshold': self.threshold,
            'total_shares': self.total_shares,
            'timestamp': self.timestamp.isoformat(),
            'access_count': self.access_count,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None,
            'metadata': json.loads(self.metadata_json) if self.metadata_json else {}
        }


class AccessLog(db.Model):
    """Audit log for vault access"""
    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.String(255), nullable=False, index=True)
    action = db.Column(db.String(50), nullable=False)  # 'store', 'retrieve', 'failed_retrieve'
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    shares_used = db.Column(db.Integer)
    error_message = db.Column(db.Text)


# Initialize vault
vault = QuantumSecureVault()

# Create tables
with app.app_context():
    db.create_all()


# API Routes

@app.route('/')
def serve_frontend():
    """Serve React frontend"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'vault_initialized': True,
        'database': 'connected'
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get vault statistics"""
    total_credentials = VaultCredential.query.count()
    total_accesses = AccessLog.query.count()
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()
    
    return jsonify({
        'total_credentials': total_credentials,
        'total_accesses': total_accesses,
        'recent_activity': [
            {
                'credential_id': log.credential_id,
                'action': log.action,
                'timestamp': log.timestamp.isoformat(),
                'success': log.success
            } for log in recent_logs
        ]
    })


@app.route('/api/credentials', methods=['GET'])
def list_credentials():
    """List all stored credentials (metadata only)"""
    credentials = VaultCredential.query.all()
    return jsonify({
        'credentials': [cred.to_dict() for cred in credentials],
        'total': len(credentials)
    })


@app.route('/api/store', methods=['POST'])
def store_credential():
    """
    Store a new credential
    
    Request body:
    {
        "credential_id": "unique_id",
        "credential_data": {"username": "...", "password": "..."},
        "master_password": "...",
        "threshold": 3,
        "total_shares": 5,
        "metadata": {"owner": "..."}
    }
    """
    try:
        data = request.json
        
        # Validate required fields
        required = ['credential_id', 'credential_data', 'master_password']
        if not all(field in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400
        
        credential_id = data['credential_id']
        credential_data = data['credential_data']
        master_password = data['master_password']
        threshold = data.get('threshold', 3)
        total_shares = data.get('total_shares', 5)
        metadata = data.get('metadata', {})
        
        # Check if credential already exists
        existing = VaultCredential.query.filter_by(credential_id=credential_id).first()
        if existing:
            return jsonify({'error': 'Credential ID already exists'}), 409
        
        # Perform encryption and secret sharing
        shares = vault.store_credential(
            credential_id=credential_id,
            credential_data=credential_data,
            master_password=master_password,
            threshold=threshold,
            total_shares=total_shares,
            metadata=metadata
        )
        
        # Get the vault entry
        entry = vault._load_entry(credential_id)
        
        # Store in database
        db_credential = VaultCredential(
            credential_id=credential_id,
            encrypted_data=entry.encrypted_data,
            ml_kem_ciphertext=entry.ml_kem_ciphertext,
            shares_data=json.dumps(entry.shares),
            salt=entry.salt,
            nonce=entry.nonce,
            threshold=threshold,
            total_shares=total_shares,
            metadata_json=json.dumps(metadata)
        )
        
        db.session.add(db_credential)
        
        # Log the action
        log_entry = AccessLog(
            credential_id=credential_id,
            action='store',
            ip_address=request.remote_addr,
            success=True
        )
        db.session.add(log_entry)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'credential_id': credential_id,
            'shares': shares,
            'threshold': threshold,
            'total_shares': total_shares,
            'message': f'Credential stored successfully. Distribute {total_shares} shares (need {threshold} to decrypt).'
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/retrieve', methods=['POST'])
def retrieve_credential():
    """
    Retrieve and decrypt a credential
    
    Request body:
    {
        "credential_id": "unique_id",
        "master_password": "...",
        "share_tokens": ["share1", "share2", "share3"]
    }
    """
    try:
        data = request.json
        
        # Validate required fields
        required = ['credential_id', 'master_password', 'share_tokens']
        if not all(field in data for field in required):
            return jsonify({'error': 'Missing required fields'}), 400
        
        credential_id = data['credential_id']
        master_password = data['master_password']
        share_tokens = data['share_tokens']
        
        # Check if credential exists
        db_credential = VaultCredential.query.filter_by(credential_id=credential_id).first()
        if not db_credential:
            log_entry = AccessLog(
                credential_id=credential_id,
                action='failed_retrieve',
                ip_address=request.remote_addr,
                success=False,
                error_message='Credential not found'
            )
            db.session.add(log_entry)
            db.session.commit()
            return jsonify({'error': 'Credential not found'}), 404
        
        # Attempt to retrieve
        try:
            decrypted_data = vault.retrieve_credential(
                credential_id=credential_id,
                master_password=master_password,
                share_tokens=share_tokens
            )
            
            # Update access statistics
            db_credential.access_count += 1
            db_credential.last_accessed = datetime.utcnow()
            
            # Log successful access
            log_entry = AccessLog(
                credential_id=credential_id,
                action='retrieve',
                ip_address=request.remote_addr,
                success=True,
                shares_used=len(share_tokens)
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'credential_data': decrypted_data,
                'credential_id': credential_id,
                'access_count': db_credential.access_count
            }), 200
            
        except ValueError as e:
            # Log failed access attempt
            log_entry = AccessLog(
                credential_id=credential_id,
                action='failed_retrieve',
                ip_address=request.remote_addr,
                success=False,
                shares_used=len(share_tokens),
                error_message=str(e)
            )
            db.session.add(log_entry)
            db.session.commit()
            
            return jsonify({'error': str(e)}), 401
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/credential/<credential_id>', methods=['GET'])
def get_credential_info(credential_id):
    """Get metadata about a credential (without decrypting)"""
    credential = VaultCredential.query.filter_by(credential_id=credential_id).first()
    
    if not credential:
        return jsonify({'error': 'Credential not found'}), 404
    
    return jsonify(credential.to_dict())


@app.route('/api/credential/<credential_id>/logs', methods=['GET'])
def get_credential_logs(credential_id):
    """Get access logs for a specific credential"""
    logs = AccessLog.query.filter_by(credential_id=credential_id)\
                          .order_by(AccessLog.timestamp.desc())\
                          .limit(50)\
                          .all()
    
    return jsonify({
        'logs': [
            {
                'action': log.action,
                'timestamp': log.timestamp.isoformat(),
                'success': log.success,
                'shares_used': log.shares_used,
                'error': log.error_message
            } for log in logs
        ]
    })


@app.route('/api/demo/attack', methods=['POST'])
def demo_attack():
    """
    Demo endpoint: Simulate an attack with insufficient shares
    
    Request body:
    {
        "credential_id": "demo_cred",
        "master_password": "...",
        "shares_available": 2  // Less than threshold
    }
    """
    try:
        data = request.json
        credential_id = data['credential_id']
        
        # Get the credential
        db_credential = VaultCredential.query.filter_by(credential_id=credential_id).first()
        if not db_credential:
            return jsonify({'error': 'Credential not found'}), 404
        
        shares = json.loads(db_credential.shares_data)
        shares_to_use = data.get('shares_available', db_credential.threshold - 1)
        
        # Attempt with insufficient shares
        try:
            vault.retrieve_credential(
                credential_id=credential_id,
                master_password=data['master_password'],
                share_tokens=shares[:shares_to_use]
            )
            return jsonify({'attack_success': True, 'message': 'Attack succeeded (unexpected!)'}), 200
        except ValueError as e:
            return jsonify({
                'attack_success': False,
                'message': 'Attack failed - insufficient shares!',
                'error': str(e),
                'shares_used': shares_to_use,
                'threshold': db_credential.threshold,
                'defense': 'Threshold secret sharing protected the credential'
            }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=True)
