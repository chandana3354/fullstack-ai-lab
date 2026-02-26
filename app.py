from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from datetime import timedelta, datetime
import bcrypt
import os

# Flask app
app = Flask(__name__)

# JWT configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

jwt = JWTManager(app)

# In-memory "databases"
users_db = {}       # {email: hashed_password}
revoked_tokens = set()  # store JWT jti for logout

# Home route
@app.route('/')
def home():
    return render_template('index.html')


# Signup route
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if email in users_db:
        return jsonify({'error': 'Email already registered'}), 400

    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users_db[email] = hashed_password
    return jsonify({'message': 'User registered successfully'}), 201


# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    hashed_password = users_db.get(email)
    if not hashed_password or not bcrypt.checkpw(password.encode(), hashed_password.encode()):
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=email)
    refresh_token = create_refresh_token(identity=email)
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': email
    }), 200


# Refresh token route
@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify({'access_token': access_token})


# Protected route
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({
        'message': 'Access granted to protected resource',
        'user': current_user,
        'timestamp': datetime.utcnow().isoformat()
    })


# Logout route
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    revoked_tokens.add(jti)
    return jsonify({'message': 'Successfully logged out'})


# Check if token is revoked
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in revoked_tokens


# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization header required'}), 401


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
