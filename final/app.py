from flask import Flask, render_template, request, session, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from authlib.integrations.flask_client import OAuth


users = []


import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

with app.app_context():
    db.create_all()

DATABASE = 'database.db'
DB_NAME = "users.db"


def connect_db():
    return sqlite3.connect(DATABASE)

# app.config['SECRET_KEY'] = 'supersecretkey'  # Change this to a secure secret key

# login_manager = LoginManager(app)
# login_manager.login_view = 'login'

# oauth = OAuth(app)
# google = oauth.register(
#     name='google',
#     client_id='1053502051941-k1pl4acqmbobnmngtspt42ri5rsfj3e3.apps.googleusercontent.com',
#     client_secret='YOUR_GOOGLE_CLIENT_SECRET',
#     authorize_url='https://accounts.google.com/o/oauth2/auth',
#     authorize_params=None,
#     authorize_params=None,
#     request_token_url=None,
#     access_token_url='https://accounts.google.com/o/oauth2/token',
#     refresh_token_url=None,
#     redirect_uri='YOUR_REDIRECT_URI',  # Update this with your actual redirect URI
#     client_kwargs={'scope': 'openid profile email'},
# )



@app.route('/')
def index():
    db = connect_db()
    
    db.execute('''

       CREATE TABLE IF NOT EXISTS hotel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hotel_name TEXT NOT NULL,
    hotel_price REAL NOT NULL,
    hotel_amenities TEXT NOT NULL,
    hotel_comments REAL,
    hotel_location TEXT NOT NULL,
    hotel_rating REAL NOT NULL,
    hotel_memberPrice REAL,
    hotel_country TEXT NOT NULL,
    hotel_city TEXT NOT NULL,
    hotel_discount REAL,
    ImageURL TEXT
);

    ''')

    db.execute('DELETE FROM hotel')

    db.execute('''

        INSERT INTO hotel (hotel_name, hotel_price, hotel_amenities, hotel_comments,hotel_location,hotel_rating,hotel_memberPrice,hotel_country,hotel_city,hotel_discount,ImageURL) VALUES
            ('Lara Barut Collection - Ultra All Inclusive','7739','restoran,havuz,Wi-Fi,bar,Spa','11','Güzeloba Mah. Yaşar Sobutay Mah. No.: 30, Lara, Antalya, Antalya, 07235','8.2 Çok İyi','7000','Turkey','Antalya','','https://images.trvl-media.com/lodging/2000000/1210000/1207100/1207007/f5aaac97.jpg?impolicy=resizecrop&rw=1200&ra=fit'),
            ('Pearly Hotel','2274','restoran,havuz,Wi-Fi,bar,Spa','9','Akdeniz Bulvarı No.: 104, Konyaaltı, Antalya, 0707','7.9 İyi','2500','Turkey','Antalya','','https://images.trvl-media.com/lodging/77000000/76580000/76577500/76577472/d1b74eb8.jpg?impolicy=resizecrop&rw=1200&ra=fit'),
            ('Conrad Istanbul Bosphorus','11653','restoran,havuz,Wi-Fi,bar,Spa','5','Cihannüma Mah. Saray Cad. No: 5, Beşiktaş, İstanbul, İstanbul, 34353','8.9 Çok İyi','10000','Turkey','Istanbul','','https://images.trvl-media.com/lodging/1000000/20000/15300/15234/f7fddb72.jpg?impolicy=resizecrop&rw=1200&ra=fit'),
            ('Beauty Collection - Ultra All Inclusive','12345','restoran,havuz,Wi-Fi,bar,Spa','13','Güzeloba Mah. Yaşar Sobutay Mah. No.: 30, Lara, Antalya, Antalya, 07235','8.5 Çok İyi','1000','Turkey','Antalya','','https://images.trvl-media.com/lodging/2000000/1220000/1218200/1218198/f21e015e.jpg?impolicy=resizecrop&rw=1200&ra=fit'),
            ('Pearly Harbour Hotel','3425','restoran,havuz,Wi-Fi,bar,Spa','17','Akdeniz Bulvarı No.: 104, Konyaaltı, Antalya, 0707','7.6 İyi','2500','Turkey','Antalya','','https://images.trvl-media.com/lodging/57000000/56210000/56204700/56204677/7426f947.jpg?impolicy=resizecrop&rw=1200&ra=fit'),
            ('Conrad Palace','8753','restoran,havuz,Wi-Fi,bar,Spa','2','Cihannüma Mah. Saray Cad. No: 5, Beşiktaş, İstanbul, İstanbul, 34353','8.8 Çok İyi','6000','Turkey','Istanbul','','https://images.trvl-media.com/lodging/92000000/91650000/91643300/91643256/fbeb73ee.jpg?impolicy=resizecrop&rw=1200&ra=fit')
        ''')

    db.commit()

    # cursor = db.execute('SELECT * FROM hotel ORDER BY hotel_price DESC')
    cursor = db.execute('SELECT * FROM hotel ORDER BY hotel_price DESC LIMIT 3')    
    hotels = cursor.fetchall()

    db.close()

    # return render_template('index.html', hotels=hotels)
    return render_template('index.html', hotels=hotels, name=request.args.get('name')) 

@app.route('/detail/<int:hotel_id>')
def detail(hotel_id):
    db = connect_db()
    cursor = db.execute('SELECT * FROM hotel WHERE id = ?', (hotel_id,))
    hotel = cursor.fetchone()
    db.close()

    return render_template('detail.html', hotel=hotel, logged_in=current_user.is_authenticated)



@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('index', name=user.name)) 

    return render_template("login.html", logged_in=current_user.is_authenticated)




@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get('email')
        
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash("Password and Confirm Password do not match.")
            return redirect(url_for('signup'))

        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalnum() and not char.isalpha() for char in password):
            flash("Password must be at least 8 characters long, contain at least 1 number, and 1 non-alphanumeric character.")
            return redirect(url_for('signup'))

        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            email=email,
            password=hash_and_salted_password,
            name=request.form.get('name'),
        )
        
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for("login"))

    return render_template("signup.html", logged_in=current_user.is_authenticated)
#     if request.method == "POST":
#         email = request.form.get('email')
        
#         result = db.session.execute(db.select(User).where(User.email == email))
#         user = result.scalar()
#         if user:
#             flash("You've already signed up with that email, log in instead!")
#             return redirect(url_for('login'))

#         password = request.form.get('password')
#         if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalnum() and not char.isalpha() for char in password):
#             flash("Password must be at least 8 characters long, contain at least 1 number, and 1 non-alphanumeric character.")
#             return redirect(url_for('signup'))

#         hash_and_salted_password = generate_password_hash(
#             password,
#             method='pbkdf2:sha256',
#             salt_length=8
#         )

#         new_user = User(
#             email=email,
#             password=hash_and_salted_password,
#             name=request.form.get('name'),
#         )
        
#         db.session.add(new_user)
#         db.session.commit()

#         login_user(new_user)
#         return redirect(url_for("login"))

#     return render_template("signup.html", logged_in=current_user.is_authenticated)




@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/search', methods=['POST'])
def search():
    if request.method == 'POST':
        city_query = request.form.get('city_query')
        selected_date = request.form.get('selected_date')

        if not city_query:
            return render_template('index.html', hotels=[], error="Please enter a city for the search")

        db = connect_db()
        cursor = db.execute('SELECT * FROM hotel WHERE hotel_city LIKE ? ORDER BY hotel_price DESC', ('%' + city_query + '%',))
        search_results = cursor.fetchall()
        db.close()

        return render_template('searchresult.html', search_results=search_results, selected_date=selected_date)
    else:
        return redirect(url_for('index'))
    

# @app.route('/login/google')
# def login_google():
#     return google.authorize_redirect(url_for('google_auth', _external=True))

# @app.route('/login/google/callback')
# def google_auth():
#     google.authorize_access_token()
#     user_info = google.get('userinfo')
#     user_email = user_info['email']

#     # Check if the user is already registered
#     user = User.query.filter_by(email=user_email).first()
#     if user is None:
#         # Create a new user
#         user = User(email=user_email, name=user_info['name'])
#         db.session.add(user)
#         db.session.commit()

#     login_user(user)
#     return redirect(url_for('index', name=user.name))

if __name__ == '__main__':
    app.run(debug=True, port=5001)

