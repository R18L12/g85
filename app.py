from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///letters.db'
app.secret_key = "supersecretkey"  # session handling
db = SQLAlchemy(app)

# ----------------------
# Database Models
# ----------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # hashed password
    security_question = db.Column(db.String(200), nullable=False)
    security_answer = db.Column(db.String(200), nullable=False)  # hashed answer


class Letter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    recipient = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='letters')


# ----------------------
# Middleware: Require login
# ----------------------
@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'forgot_password', 'verify_security', 'reset_password', 'static', 'credits']
    if request.endpoint not in allowed_routes and 'user' not in session:
        return redirect(url_for('login'))


# ----------------------
# Login Route
# ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = user.username
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Password is wrong")
    return render_template('login.html')


# ----------------------
# Register Route
# ----------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        security_question = request.form['security_question'].strip()
        security_answer = request.form['security_answer'].strip()

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="This account already exists")

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            security_question=security_question,
            security_answer=generate_password_hash(security_answer)
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html')


# ----------------------
# Logout
# ----------------------
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


# ----------------------
# Forgot Password
# ----------------------
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username'].strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('forgot_password.html', error="Password is wrong")
        return render_template('security_question.html', username=username, question=user.security_question)
    return render_template('forgot_password.html')


@app.route('/verify_security', methods=['POST'])
def verify_security():
    username = request.form['username']
    answer = request.form['security_answer'].strip()
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.security_answer, answer):
        return render_template('reset_password.html', username=username)
    else:
        return render_template('forgot_password.html', error="Password is wrong")


@app.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form['username']
    new_password = request.form['new_password'].strip()
    user = User.query.filter_by(username=username).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
    return redirect(url_for('login'))


# ----------------------
# Home page: user-specific letters
# ----------------------
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()
    if not user:
        session.pop('user', None)
        return redirect(url_for('login'))

    query = request.args.get('q')
    if query:
        letters = Letter.query.filter(
            Letter.deleted == False,
            Letter.user_id == user.id,
            (Letter.sender.like(f"%{query}%")) |
            (Letter.recipient.like(f"%{query}%"))
        ).all()
    else:
        letters = Letter.query.filter_by(deleted=False, user_id=user.id).all()
    
    return render_template('index.html', letters=letters)


# ----------------------
# Add letter
# ----------------------
@app.route('/add', methods=['GET', 'POST'])
def add():
    user = User.query.filter_by(username=session['user']).first()
    if request.method == 'POST':
        new_letter = Letter(
            sender=request.form['sender'],
            recipient=request.form['recipient'],
            subject=request.form['subject'],
            content=request.form['content'],
            user_id=user.id
        )
        db.session.add(new_letter)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add.html')


# ----------------------
# Edit, Delete, Trash (user-specific)
# ----------------------
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    user = User.query.filter_by(username=session['user']).first()
    letter = Letter.query.filter_by(id=id, user_id=user.id).first_or_404()
    if request.method == 'POST':
        letter.sender = request.form['sender']
        letter.recipient = request.form['recipient']
        letter.subject = request.form['subject']
        letter.content = request.form['content']
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit.html', letter=letter)


@app.route('/delete/<int:id>')
def delete(id):
    user = User.query.filter_by(username=session['user']).first()
    letter = Letter.query.filter_by(id=id, user_id=user.id).first_or_404()
    letter.deleted = True
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/trash')
def trash():
    user = User.query.filter_by(username=session['user']).first()
    letters = Letter.query.filter_by(deleted=True, user_id=user.id).all()
    return render_template('trash.html', letters=letters)


@app.route('/restore/<int:id>')
def restore(id):
    user = User.query.filter_by(username=session['user']).first()
    letter = Letter.query.filter_by(id=id, user_id=user.id).first_or_404()
    letter.deleted = False
    db.session.commit()
    return redirect(url_for('trash'))


@app.route('/hard_delete/<int:id>')
def hard_delete(id):
    user = User.query.filter_by(username=session['user']).first()
    letter = Letter.query.filter_by(id=id, user_id=user.id).first_or_404()
    db.session.delete(letter)
    db.session.commit()
    return redirect(url_for('trash'))


# ----------------------
# Credits Page
# ----------------------
@app.route('/credits')
def credits():
    members = [
        {"name": "Akpabli Desmond Cudjoe Delali", "index": "22325879", "img": "img/member1.jpeg", "role": "Lead Developer & Project Coordinator"},
        {"name": "Sylvester Awidi Bart-plange", "22398329": "", "img": "img/member2.jpeg", "role": "Backend Developer"},
        {"name": "Member 3", "index": "XXXXXXXX", "img": "img/member3.jpeg", "role": "Frontend Developer"},
        {"name": "Member 4", "index": "XXXXXXXX", "img": "img/member4.jpeg", "role": "Database & API Integration"},
        {"name": "Chelsea Acheampong", "index": "10833237", "img": "img/member5.jpeg", "role": "UI/UX Designer"},
        {"name": "Member 6", "index": "XXXXXXXX", "img": "img/member6.jpeg", "role": "Tester & QA"},
        {"name": "Member 7", "index": "XXXXXXXX", "img": "img/member7.jpeg", "role": "Documentation & Reports"},
        {"name": "Member 8", "index": "XXXXXXXX", "img": "img/member8.jpeg", "role": "Video & Presentation"},
    ]
    return render_template('credits.html', members=members)


# ----------------------
# Run App
# ----------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print("🚀 Flask app running at http://127.0.0.1:5000")
    app.run(debug=True)
