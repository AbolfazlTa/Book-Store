from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta
import sqlite3




app = Flask(__name__)




app.config['JWT_SECRET_KEY'] = 'secretkey'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)




bcrypt = Bcrypt(app)
jwt = JWTManager(app)
DATABASE = 'login.db'




def get_db_connection():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db





def create_tables():
    db = get_db_connection()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS books (
                    id INTEGER PRIMARY KEY,
                    title TEXT NOT NULL,
                    price REAL NOT NULL,
                    category TEXT NOT NULL,
                    author TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS purchases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    book_id INTEGER NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(book_id) REFERENCES books(id)
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    book_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    comment TEXT NOT NULL,
                    FOREIGN KEY(book_id) REFERENCES books(id),
                    FOREIGN KEY(user_id) REFERENCES users(id)
                  )''')
    db.commit()
    db.close()
    books_table()





def books_table():
    books = [
        (1, "The Great Gatsby", 10.99, "Fiction", "F. Scott Fitzgerald"),
        (2, "To Kill a Mockingbird", 12.99, "Fiction", "Harper Lee"),
        (3, "1984", 15.00, "Dystopian", "George Orwell"),
        (4, "Pride and Prejudice", 9.99, "Romance", "Jane Austen"),
        (5, "The Catcher in the Rye", 11.50, "Fiction", "J.D. Salinger")
    ]
    db = get_db_connection()
    cursor = db.cursor()
    cursor.executemany("INSERT OR IGNORE INTO books (id, title, price, category, author) VALUES (?, ?, ?, ?, ?)", books)
    db.commit()
    db.close()





@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    db = get_db_connection()
    cursor = db.cursor()

    if cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
        return jsonify({"message": "Username already exists"}), 400
    
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()

    return jsonify({"message": "User registered successfully"}), 201






@app.route('/admin/register', methods=['POST'])
def register_admin():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    db = get_db_connection()
    cursor = db.cursor()

    if cursor.execute("SELECT * FROM admin WHERE username = ?", (username,)).fetchone():
        return jsonify({"message": "Admin username already exists"}), 400
    
    cursor.execute("INSERT INTO admin (username, password) VALUES (?, ?)", (username, hashed_password))
    db.commit()
    db.close()

    return jsonify({"message": "Admin registered successfully"}), 201





@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    db = get_db_connection()
    cursor = db.cursor()
    
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()
    
    if not user:
        return jsonify({"message": "Invalid username"}), 401

    if not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"message": "Invalid password"}), 401

    access_token = create_access_token(identity=user['username'])
    return jsonify(access_token=access_token), 200









@app.route('/admin/home', methods=['GET'])
@jwt_required()
def admin_home():
    current_user = get_jwt_identity()
    
    db = get_db_connection()
    cursor = db.cursor()
    admin = cursor.execute("SELECT * FROM admin WHERE username = ?", (current_user,)).fetchone()
    
    if not admin:
        db.close()
        return jsonify({"message": "Access forbidden: Admins only"}), 403

    books = cursor.execute("SELECT * FROM books").fetchall()
    db.close()

    books_list = [dict(book) for book in books]

    return jsonify({
        "message": f"Welcome to the admin home page, {current_user}!",
        "books": books_list
    }), 200






@app.route('/home', methods=['GET'])
@jwt_required()
def get_books():
    db = get_db_connection()
    books = db.execute("SELECT * FROM books").fetchall()
    db.close()
    
    books_list = [dict(book) for book in books]
    return jsonify(books_list), 200






@app.route('/book/<int:book_id>', methods=['GET'])
@jwt_required()
def get_book(book_id):
    db = get_db_connection()
    book = db.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
    db.close()
    
    if book:
        return jsonify(dict(book)), 200
    else:
        return jsonify({"message": "Book not found"}), 404






@app.route('/buy', methods=['POST'])
@jwt_required()
def buy_books():
    current_user = get_jwt_identity()
    data = request.get_json()
    book_ids = data.get('book_ids', [])

    db = get_db_connection()
    cursor = db.cursor()

    user = cursor.execute("SELECT id FROM users WHERE username = ?", (current_user,)).fetchone()
    if not user:
        return jsonify({"message": "User not found"}), 404
    user_id = user["id"]

    purchases = [(user_id, book_id) for book_id in book_ids]
    cursor.executemany("INSERT INTO purchases (user_id, book_id) VALUES (?, ?)", purchases)
    db.commit()
    
    query = f"SELECT * FROM books WHERE id IN ({', '.join(['?'] * len(book_ids))})"
    books = cursor.execute(query, book_ids).fetchall()
    db.close()
    
    bought_books = [{"id": book["id"], "title": book["title"], "price": book["price"], "category": book["category"], "author": book["author"]} for book in books]
    return jsonify({
        "message": f"Books purchased successfully by {current_user}!",
        "books": bought_books
    }), 200






@app.route('/admin/books', methods=['POST', 'DELETE', 'PUT'])
@jwt_required()
def manage_books():
    current_user = get_jwt_identity()
    
    db = get_db_connection()
    cursor = db.cursor()

    if cursor.execute("SELECT * FROM admin WHERE username = ?", (current_user,)).fetchone() is None:
        return jsonify({"message": "Access forbidden: Admins only"}), 403

    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title')
        price = data.get('price')
        category = data.get('category')
        author = data.get('author')
        
        if not title or not price or not category or not author:
            return jsonify({"message": "Missing book details"}), 400

        cursor.execute("INSERT INTO books (title, price, category, author) VALUES (?, ?, ?, ?)",
                       (title, price, category, author))
        db.commit()
        db.close()
        
        return jsonify({"message": "Book added successfully"}), 201

    elif request.method == 'DELETE':
        book_id = request.args.get('book_id')
        
        if not book_id:
            return jsonify({"message": "Missing book_id parameter"}), 400

        cursor.execute("DELETE FROM books WHERE id = ?", (book_id,))
        db.commit()
        db.close()
        
        return jsonify({"message": "Book deleted successfully"}), 200

    elif request.method == 'PUT':
        data = request.get_json()
        book_id = data.get('book_id')
        title = data.get('title')
        price = data.get('price')
        category = data.get('category')
        author = data.get('author')
        
        if not book_id:
            return jsonify({"message": "Missing book_id"}), 400
        if not title and not price and not category and not author:
            return jsonify({"message": "No update fields provided"}), 400

        update_fields = []
        params = []
        if title:
            update_fields.append("title = ?")
            params.append(title)
        if price:
            update_fields.append("price = ?")
            params.append(price)
        if category:
            update_fields.append("category = ?")
            params.append(category)
        if author:
            update_fields.append("author = ?")
            params.append(author)
        params.append(book_id)

        query = f"UPDATE books SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, params)
        db.commit()
        db.close()
        
        
        return jsonify({"message": "Book updated successfully"}), 200


    return jsonify({"message": "Invalid request method"}), 405









@app.route('/comments', methods=['POST'])
@jwt_required()
def add_comment():
    current_user = get_jwt_identity()
    data = request.get_json()

    book_id = data.get('book_id')
    comment_text = data.get('comment')

    if not book_id or not comment_text:
        return jsonify({"message": "Missing book_id or comment text"}), 400

    db = get_db_connection()
    cursor = db.cursor()


    user = cursor.execute("SELECT id FROM users WHERE username = ?", (current_user,)).fetchone()
    if not user:
        db.close()
        return jsonify({"message": "User not found"}), 404
    user_id = user["id"]


    book = cursor.execute("SELECT id FROM books WHERE id = ?", (book_id,)).fetchone()
    if not book:
        db.close()
        return jsonify({"message": "Book not found"}), 404

    
    cursor.execute("INSERT INTO comments (book_id, user_id, comment) VALUES (?, ?, ?)", (book_id, user_id, comment_text))
    db.commit()
    db.close()

    return jsonify({"message": "Comment added successfully"}), 201


@app.route('/comments/<int:book_id>', methods=['GET'])
def get_comments(book_id):
    db = get_db_connection()
    comments = db.execute('''SELECT c.id, u.username, c.comment 
                              FROM comments c
                              JOIN users u ON c.user_id = u.id
                              WHERE c.book_id = ?''', (book_id,)).fetchall()
    db.close()

    comments_list = [{"id": comment["id"], "username": comment["username"], "comment": comment["comment"]} for comment in comments]
    return jsonify(comments_list), 200





if __name__ == '__main__':
    create_tables()
    app.run(debug=True)

