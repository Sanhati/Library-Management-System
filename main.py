from fastapi import FastAPI,responses,Depends, HTTPException, status, Request
from asyncpg import create_pool
from typing import List
from pydantic import BaseModel
import psycopg2
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional
from datetime import datetime, timedelta
import asyncpg


app = FastAPI()

database_url = "postgresql://sanhati:12062023@localhost/postgres"
pool = None
async def get_pool():
    global pool
    if pool is None:
        pool = await create_pool(database_url)
    return pool

conn = psycopg2.connect(
    dbname="postgres",
    user="sanhati",
    password="12062023",
    host="127.0.0.1",
    port="5432"
)

@app.get("/")
async def default_page():
    html_content = """
    <html>
    <head>
        <title>Welcome to the Library Management System</title>
    </head>
    <body>
        <h1>Welcome</h1>
        <p>This is the default page of the Library Management System.</p>
    </body>
    </html>
    """
    return responses.HTMLResponse(content=html_content, status_code=200)

class Book(BaseModel):
    book_id: int
    title: str
    author: str
    publication_year: int

#list all books
@app.get("/books", response_model=List[Book])
async def list_books():
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM books")
    results = cursor.fetchall()
    cursor.close()
    books = []
    
    for result in results:
        book_id, title, author, publication_date = result
        books.append(Book(book_id=book_id, title=title, author=author, publication_year=publication_date))
    #return books
    book_items = ""
    for book in books:
        book_items += f"<li>{book.title} - {book.author} ({book.publication_year})</li>"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>List of Books</title>
    </head>
    <body>
        <h1>List of Books</h1>
        <ul>
            {book_items}
        </ul>
    </body>
    </html>
    """
    return responses.HTMLResponse(content=html_content, status_code=200)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class User(BaseModel):
    user_id: int
    username: str
    password: str
    email: str
    role: str
    disabled: bool | None = None

async def close_pool():
    if pool is not None:
        await pool.close()@app.on_event("startup")

async def startup_event():
    await get_pool()@app.on_event("shutdown")

async def shutdown_event():
    await close_pool()


@app.post("/register")
async def register(request: Request, username: str, password: str, email: str, role: str):
    connection = await (await get_pool()).acquire()
    try:
        async with connection.transaction():
            hashed_password = get_password_hash(password) 
            await connection.execute(
                "INSERT INTO users (username, password, email, role) VALUES ($1, $2, $3, $4)",
                username, hashed_password, email, role
            )

        return {"message": "User registered successfully"}
    finally:
        await (await get_pool()).release(connection)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserInDB(User):
    hashed_password: str
    user_id: int
    password: Optional[str] = None
    role: Optional[str] = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(username: str):
    query = "SELECT * FROM users WHERE username = %s;"
    with conn.cursor() as cursor:
        cursor.execute(query, (username,))
        user_row = cursor.fetchone()
        if user_row:
            user_dict = {
                "user_id":user_row[0],
                "username": user_row[1],
                "email": user_row[3],
                "role":user_row[4], 
                "disabled": False,  
                "hashed_password": user_row[2],
            }
            return UserInDB(**user_dict)
        
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# async def get_current_user(token= Depends(oauth2_scheme)):
#     credentials_exception = HTTPException(
#         status_code=status.HTTP_401_UNAUTHORIZED,
#         detail="Could not validate credentials",
#         headers={"WWW-Authenticate": "Bearer"},
#     )
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise credentials_exception
#         token_data = TokenData(username=username)
#     except JWTError:
#         raise credentials_exception
#     user = get_user(username=token_data.username)
#     if user is None:
#         raise credentials_exception
#     return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user(username)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid user")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_active_user(
    current_user= Depends(get_current_user)
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/users/me")
async def get_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm= Depends()
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/books")
async def create_book(request: Request,
    book_id:int, title:str, author:str, publication_year:int,
    current_user: User = Depends(get_current_user)
    
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="User not authorized")
    
    query = "INSERT INTO books (book_id, title, author, publication_year) VALUES (%s ,%s, %s, %s) RETURNING book_id;"
    with conn.cursor() as cursor:
        cursor.execute(query, (book_id,title, author, publication_year))
        book_id = cursor.fetchone()[0]
        conn.commit()
    
    return {"book_id": book_id, "message": "Book created successfully"}

from datetime import date

@app.post("/issue-book/{book_id}")
async def issue_book(book_id: int, current_user: User = Depends(get_current_user)):
    if current_user.role == "admin":
        raise HTTPException(status_code=403, detail="Admins are not allowed to issue books.")

    issue_date = date.today()
    return_date = None  

    query = "INSERT INTO issue (user_id, book_id, issue_date, return_date) VALUES (%s, %s, %s, %s) RETURNING issue_id;"
    values = (current_user.user_id, book_id, issue_date, return_date)

    with conn.cursor() as cursor:
        cursor.execute(query, values)
        issue_id = cursor.fetchone()[0]
        conn.commit()

    return {"issue_id": issue_id, "user_id": current_user.user_id, "book_id": book_id, "issue_date": issue_date, "return_date": return_date}


from datetime import date

@app.put("/books/{book_id}/return")
async def return_book(
    book_id: int,
    current_user: User = Depends(get_current_active_user)
):
    if current_user.role == "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only normal users are allowed to return books"
        )
    
    query = "SELECT * FROM issue WHERE user_id = %s AND book_id = %s;"
    with conn.cursor() as cursor:
        cursor.execute(query, (current_user.user_id, book_id))
        issue_row = cursor.fetchone()
        
        if not issue_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Book not issued by the user"
            )
        
        issue_id = issue_row[0]
        issue_date = issue_row[3]
        return_date = date.today()

        update_query = "UPDATE issue SET return_date = %s WHERE issue_id = %s;"
        cursor.execute(update_query, (return_date, issue_id))
        conn.commit()
    
    return {"message": "Book returned successfully"}
