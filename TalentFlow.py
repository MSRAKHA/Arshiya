
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sqlite3
import os 
import io
import time
import plotly.express as px
from hashlib import sha256
import pytz
import os
import secrets

# At the very top of your script
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = None
    st.session_state['role'] = None
    st.session_state['initialized'] = False
    st.session_state.permanent = True
    
os.environ['TZ'] = 'Asia/Kolkata'  # Set to your timezone
try:
    time.tzset()  # This will work on Unix systems
except AttributeError:
    pass  # Windows doesn't have time.tzset()




st.set_page_config(layout="wide",page_title = "TalentFlow" , page_icon="🧑‍💻" )

#Add this function to handle Excel file validation:
def log_login_session(username):
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    try:
        
        local_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        c.execute('''
            INSERT INTO user_sessions (username, login_time)
            VALUES (?, ?)
        ''', (username,local_time))
        conn.commit()
    finally:
        conn.close()



def generate_reset_token():
    return secrets.token_urlsafe(32)

def create_password_reset_token(username):
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    try:
        # Check if user exists
        c.execute("SELECT username FROM users WHERE username=?", (username,))
        if not c.fetchone():
            return False, "User not found"
        
        # Generate token and expiration
        token = generate_reset_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        # Store token in database
        c.execute('''
            INSERT INTO password_resets (username, reset_token, expires_at)
            VALUES (?, ?, ?)
        ''', (username, token, expires_at))
        conn.commit()
        return True, token
    except sqlite3.Error as e:
        return False, str(e)
    finally:
        conn.close()

def verify_reset_token(token):
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    try:
        c.execute('''
            SELECT username FROM password_resets 
            WHERE reset_token = ? 
            AND used = FALSE 
            AND expires_at > CURRENT_TIMESTAMP
        ''', (token,))
        result = c.fetchone()
        return result[0] if result else None
    finally:
        conn.close()

def reset_password(token, new_password):
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    try:
        username = verify_reset_token(token)
        if not username:
            return False, "Invalid or expired token"
        
        # Update password
        hashed_password = hash_password(new_password)
        c.execute("UPDATE users SET password = ? WHERE username = ?", 
                 (hashed_password, username))
        
        # Mark token as used
        c.execute("UPDATE password_resets SET used = TRUE WHERE reset_token = ?", 
                 (token,))
        conn.commit()
        return True, "Password reset successful"
    except sqlite3.Error as e:
        return False, str(e)
    finally:
        conn.close()

def validate_excel_data(df):
    required_columns = ['emp_id', 'fullname', 'phone', 'skills', 'location', 
                       'hands_on_skills', 'total_experience', 'grade', 'employer_id']
    
    # Check if all required columns exist
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        return False, f"Missing columns: {', '.join(missing_columns)}"
    
    # Validate data types and formats
    for index, row in df.iterrows():
        # Check if emp_id is numeric
        if not str(row['emp_id']).isdigit():
            return False, f"Invalid Employee ID at row {index + 2}: Must be numeric"
        
        # Check if phone is 10 digits
        if not str(row['phone']).isdigit() or len(str(row['phone'])) != 10:
            return False, f"Invalid phone number at row {index + 2}: Must be 10 digits"
        
        # Check if fullname contains only alphabets and spaces
        if not str(row['fullname']).replace(" ", "").isalpha():
            return False, f"Invalid name at row {index + 2}: Must contain only alphabets"
        
        # Check if employer_id is numeric
        if not str(row['employer_id']).isdigit():
            return False, f"Invalid Employer ID at row {index + 2}: Must be numeric"
    
    return True, "Validation successful"
def show_login_statistics():
    conn = sqlite3.connect('candidate_evaluation.db')
    try:
        # For regular users - show only their statistics
        # query = '''
        #     SELECT 
        #         MAX(login_time) as last_login,
        #         COUNT(*) as total_sessions,
        #         COALESCE(AVG(session_duration), 0) as avg_duration_minutes,
        #         COALESCE(SUM(session_duration), 0) as total_duration_minutes
        #     FROM user_sessions
        #     WHERE username = ?
        # '''
        query = '''
            SELECT 
                strftime('%Y-%m-%d %H:%M:%S', login_time, 'localtime') as login_time,
                COUNT(*) as total_sessions,
                COALESCE(AVG(session_duration), 0) as avg_duration_minutes,
                COALESCE(SUM(session_duration), 0) as total_duration_minutes
            FROM user_sessions
            WHERE username = ?
        '''
        df = pd.read_sql_query(query, conn, params=(st.session_state['username'],))
        
        st.subheader("Your Login Statistics")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Sessions", int(df['total_sessions'].iloc[0]))
        with col2:
            # Handle null/zero values
            avg_duration = df['avg_duration_minutes'].iloc[0]
            avg_duration = 0 if pd.isna(avg_duration) else float(avg_duration)
            st.metric("Average Session (min)", round(avg_duration, 2))
        with col3:
            # Handle null/zero values
            total_duration = df['total_duration_minutes'].iloc[0]
            total_duration = 0 if pd.isna(total_duration) else float(total_duration)
            st.metric("Total Time (min)", round(total_duration, 2))


        # Show recent sessions
        recent_sessions = pd.read_sql_query('''
            SELECT 
                strftime('%d/%m/%Y %I:%M:%S %p', login_time) as login_time,
                CASE 
                    WHEN logout_time IS NULL THEN 'Active'
                    ELSE strftime('%d/%m/%Y %I:%M:%S %p', logout_time)
                END as logout_time,
                COALESCE(session_duration, 0) as duration_minutes
            FROM user_sessions
            WHERE username = ?
            ORDER BY login_time DESC
            LIMIT 5
        ''', conn, params=(st.session_state['username'],))
        
        if not recent_sessions.empty:
            st.subheader("Recent Sessions")
            # Remove the datetime conversion since we're already formatting in SQL
            st.dataframe(recent_sessions)
        else:
            st.info("No session history available yet.")
            
    finally:
        conn.close()

def show_user_activity_dashboard():
    st.markdown("### :blue[**Activity Dashboard**]")
    
    conn = sqlite3.connect('candidate_evaluation.db')
    
    try:
        # Different queries based on role
        if st.session_state.role == 'admin':
            # Admin can see all activities
            query = """
            SELECT 
                username,
                action_type,
                COUNT(*) as count,
                MAX(timestamp) as last_activity,
                COALESCE(AVG(CASE 
                    WHEN duration IS NULL THEN 0 
                    ELSE CAST(duration AS FLOAT) 
                END), 0) as avg_duration
            FROM user_activity
            GROUP BY username, action_type
            ORDER BY username, last_activity DESC
            """
            df = pd.read_sql_query(query, conn)
        else:
            # Regular users can only see their own activities
            query = """
            SELECT 
                action_type,
                COUNT(*) as count,
                MAX(timestamp) as last_activity,
                COALESCE(AVG(CASE 
                    WHEN duration IS NULL THEN 0 
                    ELSE CAST(duration AS FLOAT) 
                END), 0) as avg_duration
            FROM user_activity
            WHERE username = ?
            GROUP BY action_type
            ORDER BY last_activity DESC
            """
            df = pd.read_sql_query(query, conn, params=(st.session_state.username,))

        # Handle empty DataFrame
        if df.empty:
            st.info("No activity data available.")
            return

        # Convert avg_duration to numeric, replacing any remaining NaN with 0
        if 'avg_duration' in df.columns:
            df['avg_duration'] = pd.to_numeric(df['avg_duration'], errors='coerce').fillna(0)
            # Now it's safe to round
            df['avg_duration'] = df['avg_duration'].apply(lambda x: round(float(x), 2))

        # Display metrics based on role
        if st.session_state.role == 'admin':
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Users", len(df['username'].unique()))
            with col2:
                st.metric("Total Activities", len(df))
            with col3:
                today_activities = len(df[df['last_activity'].str.contains(datetime.now().strftime('%Y-%m-%d'), na=False)])
                st.metric("Today's Activities", today_activities)
            with col4:
                st.metric("Different Actions", df['action_type'].nunique())
        else:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Activities", len(df))
            with col2:
                today_activities = len(df[df['last_activity'].str.contains(datetime.now().strftime('%Y-%m-%d'), na=False)])
                st.metric("Today's Activities", today_activities)
            with col3:
                st.metric("Different Actions", df['action_type'].nunique())

        # Show detailed activity log
        st.subheader("Recent Activities")
        if st.session_state.role == 'admin':
            detailed_query = """
            SELECT 
                username,
                timestamp,
                action_type,
                action_details
            FROM user_activity
            ORDER BY timestamp DESC
            LIMIT 50
            """
            activities = pd.read_sql_query(detailed_query, conn)
        else:
            detailed_query = """
            SELECT 
                timestamp,
                action_type,
                action_details
            FROM user_activity
            WHERE username = ?
            ORDER BY timestamp DESC
            LIMIT 50
            """
            activities = pd.read_sql_query(detailed_query, conn, 
                                         params=(st.session_state.username,))

        # Display activities
        if not activities.empty:
            for _, activity in activities.iterrows():
                with st.container():
                    if st.session_state.role == 'admin':
                        col1, col2, col3 = st.columns([2, 2, 8])
                        with col1:
                            st.text(activity['timestamp'].split('.')[0] if activity['timestamp'] else '')
                        with col2:
                            st.text(activity['username'])
                        with col3:
                            st.write(f"**{activity['action_type']}**: {activity['action_details']}")
                    else:
                        col1, col2 = st.columns([2, 8])
                        with col1:
                            st.text(activity['timestamp'].split('.')[0] if activity['timestamp'] else '')
                        with col2:
                            st.write(f"**{activity['action_type']}**: {activity['action_details']}")
        else:
            st.info("No activity records found.")
            
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")
    finally:
        conn.close()

def process_excel_upload(excel_file):
    try:
        # Read the Excel file
        df = pd.read_excel(excel_file)
        #error handling for empty files
        if df.empty:
            return False, "The uploaded file is empty. Please upload a valid Excel file."
        #error handling for invalid file types
        if not excel_file.name.endswith('.xlsx'):
            return False, "Invalid file type. Please upload an Excel file (.xlsx)"
        
        
        # Validate the data
        is_valid, message = validate_excel_data(df)
        if not is_valid:
            return False, message
        
        # Connect to database
        conn = sqlite3.connect('candidate_evaluation.db')
        cursor = conn.cursor()
        
        # Initialize counters
        success_count = 0
        error_count = 0
        errors = []
        
        # Process each row
        for index, row in df.iterrows():
            try:
                # Set interview status as Pending for new entries
                interview_status = "Pending"
                
                # Insert data into database
                cursor.execute('''
                    INSERT INTO candidates (
                        emp_id, fullname, phone, skills, location, hands_on_skills, 
                        total_experience, grade, employer_id, interview_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(row['emp_id']), row['fullname'], str(row['phone']), 
                    row['skills'], row['location'], row['hands_on_skills'],
                    str(row['total_experience']), row['grade'], 
                    str(row['employer_id']), interview_status
                ))
                success_count += 1
            
            except sqlite3.IntegrityError:
                error_count += 1
                errors.append(f"Row {index + 2}: Employee ID {row['emp_id']} already exists")
                
            except Exception as e:
                error_count += 1
                errors.append(f"Row {index + 2}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        return True, f"Successfully added {success_count} records. {error_count} errors occurred.\n" + "\n".join(errors)
        
    except Exception as e:
        return False, f"Error processing file: {str(e)}"



# Add login related functions here
def create_login_table():
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, 
                  password TEXT,
                  role TEXT)''')
    conn.commit()
    conn.close()

def hash_password(password):
    return sha256(password.encode()).hexdigest()

def add_test_user():
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    username = "Admin"
    password = hash_password("Admin@123")
    role = "admin"
    try:
        c.execute("INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)",
                 (username, password, role))
        conn.commit()
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
    finally:
        conn.close()


def verify_login(username, password):
    with sqlite3.connect('candidate_evaluation.db') as conn:
        try:
            c = conn.cursor()
            c.execute("SELECT password, role FROM users WHERE username=?", 
                     (username,))
            result = c.fetchone()
            if result and result[0] == hash_password(password):
                
                login_success(username, result[1])
                log_login_session(username)
                return True, result[1]
            return False, None
        except sqlite3.Error:
            return False, None
	
# In your login function, after successful login:
def login_success(username, role):
    st.session_state['logged_in'] = True
    st.session_state['username'] = username
    st.session_state['role'] = role
    st.session_state['initialized'] = True


def signup_page():
    st.title("**:rainbow[Signup]**")
    
    left_col, right_col = st.columns([3, 9])
    with left_col:
        st.image("su.jpg", width=250)
        #st.video("vilp.mp4")

    
    with right_col:
        # Signup form
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        role = st.selectbox("Role", ["user", "admin"])
        
        if st.button("Sign Up"):
            if not username or not password or not confirm_password:
                st.error("Please fill in all fields")
                st.toast("Please fill all fields", icon="❌")
                return False
            
            if password != confirm_password:
                st.error("Passwords do not match")
                st.toast("Passwords do not match", icon="❌")
                return False
            
            conn = sqlite3.connect('candidate_evaluation.db')
            c = conn.cursor()
            
            try:
                # Check if username already exists
                c.execute("SELECT username FROM users WHERE username=?", (username,))
                if c.fetchone():
                    st.error("Username already exists")
                    st.toast("Username already exists", icon="❌")
                    return False
                
                # Insert new user
                hashed_password = hash_password(password)
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                         (username, hashed_password, role))
                conn.commit()
                
                st.success("Signup successful! Please login.")
                st.toast("Signup successful!", icon="✅")
                return True
            
            except sqlite3.Error as e:
                st.error(f"Database error: {e}")
                return False
            finally:
                conn.close()
    
    # with left_col:
    #     st.write("Join TalentFlow - Streamline Your Engineering Talent Management")
def login_page():
    if st.session_state.get('logged_in', False):
        return 
    st.header("**:rainbow[Welcome to TalentFlow - Your Partner in Talent Acquisition!]**")

    tab1, tab2, tab3 = st.tabs(["Login", "Sign Up","Reset Password"])
    
    with tab1:
        st.title("**:rainbow[Login]**")
        left_col, right_col = st.columns([3,9])
        with left_col:
            st.image("login.jpg", width=250)

        
        with right_col:
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            
            # Store form submission in a variable
            login_clicked = st.button("Login", key="login_button")
            
            if login_clicked:  # Check button click first
                if not username or not password:
                    st.error("Please enter both username and password")
                    st.toast("Please fill all fields", icon="❌")
                    return False
                
                try:
                    success, role = verify_login(username, password)
                    
                    if success:
                       
                        st.session_state['logged_in'] = True
                        st.session_state['username'] = username
                        st.session_state['role'] = role
                        
                        st.success("Login successful!")
                         
                        st.rerun()  
                        
                    else:
                        st.error("Invalid username or password")
                        st.toast("Login failed", icon="❌")
                        return False
                        
                except Exception as e:
                    st.error(f"An error occurred: {str(e)}")
                    return False
    
    with tab2:
        signup_page()

    
    with tab3:
        st.title("**:rainbow[Reset Password]**")
        reset_step = st.session_state.get('reset_step', 'request')
        
        if reset_step == 'request':
            username = st.text_input("Enter your username")
            if st.button("Request Password Reset", key="reset_request_button"):
                if username:
                    success, token = create_password_reset_token(username)
                    if success:
                        st.session_state.reset_token = token
                        st.session_state.reset_step = 'reset'
                        st.success("Reset token generated. Please enter your new password.")
                        st.rerun()
                    else:
                        st.error(f"Error: {token}")
                else:
                    st.warning("Please enter your username")
        
        elif reset_step == 'reset':
            new_password = st.text_input("New Password", type="password",key="reset_new_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="reset_confirm_password")
            
            if st.button("Reset Password", key="reset_password_button"):
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters long")
                else:
                    success, message = reset_password(
                        st.session_state.reset_token, 
                        new_password
                    )
                    if success:
                        st.success(message)
                        # Clear reset state
                        st.session_state.pop('reset_step', None)
                        st.session_state.pop('reset_token', None)
                        st.rerun()
                    else:
                        st.error(message)

# Initialize login system
create_login_table()
if not st.session_state.get('initialized'):
    add_test_user()
    st.session_state['initialized'] = True

# Check login status
if not st.session_state['logged_in']:
    login_page()
    st.stop()  # Stop execution if not logged in




def log_logout_session(username):
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    try:
        
        local_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Update the most recent session for this user
        c.execute('''
            UPDATE user_sessions 
            SET logout_time = ? ,
                session_duration = ROUND((JULIANDAY(?) - 
                                       JULIANDAY(login_time)) * 24 * 60)
            WHERE username = ? 
            AND logout_time IS NULL
        ''', (local_time,local_time,username))
        conn.commit()
    finally:
        conn.close()

def set_page_style():
    # Custom CSS for the entire app
    st.markdown("""
        <style>
        /* Main page background and text */
        .stApp {
            background: #f0f2f6;
            color: #1f1f1f;
        }
        
        /* Header styling */
        .main-header {
            background-color: #1f4788;
            padding: 1.5rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        
        /* Card styling */
        .custom-card {
            background-color: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            margin-bottom: 1rem;
        }
        
        /* Subheader styling */
        .custom-subheader {
            background-color: #2e5ca5;
            padding: 0.8rem;
            border-radius: 5px;
            color: white;
            margin-bottom: 1rem;
        }
        
        /* Button styling */
        .stButton>button {
            background-color: #1f4788;
            color: white;
            border-radius: 5px;
            padding: 0.5rem 1rem;
            border: none;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        
        .stButton>button:hover {
            background-color: #2e5ca5;
            border: none;
        }
        
        /* Sidebar styling */
        .css-1d391kg {
            background-color: #1f4788;
        }
        
        /* Input fields styling */
        .stTextInput>div>div>input {
            border-radius: 5px;
        }
        
        /* Select box styling */
        .stSelectbox>div>div>select {
            border-radius: 5px;
        }
        
        /* Custom colors for different pages */
        .new-candidate-page {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        }
        
        .reports-page {
            background: linear-gradient(135deg, #f1f8ff 0%, #e3f2fd 100%);
        }       
        /* Status indicators */
        .status-pending {
            background-color: #ffd700;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            color: black;
            font-weight: bold;
        }

        .status-Pending {
    background-color: #ffd700;
    padding: 0.3rem 0.8rem;
    border-radius: 15px;
    color: black;
    font-weight: bold;
}
        
        .status-Selected {
            background-color: #28a745;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            color: white;
            font-weight: bold;
        }
        
        .status-rejected {
            background-color: #dc3545;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            color: white;
            font-weight: bold;
        }
        
        .status-trial {
            background-color: #17a2b8;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            color: white;
            font-weight: bold;
        }
        
        /* Metrics styling */
        .metric-card {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        .metric-value {
            font-size: 24px;
            font-weight: bold;
            color: #1f4788;
        }
        
        .metric-label {
            color: #666;
            font-size: 14px;
        }
        </style>
    
    """, unsafe_allow_html=True)
def style_button_advanced(
    background_color="blue",
    text_color="white",
    border_radius="5px",
    width="100%",
    hover_color=None
):
    hover_color = hover_color or background_color
    button_styles = f"""
        <style>
        .stButton>button {{
            background-color: {background_color};
            color: {text_color};
            border-radius: {border_radius};
            padding: 0.5rem 1rem;
            border: none;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            width: {width};
            margin: 4px 0;
            transition: all 0.3s ease;
        }}
        
        .stButton>button:hover {{
            background-color: {hover_color};
            opacity: 0.8;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        }}
        
        .stButton>button:active {{
            transform: translateY(2px);
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        }}
        
        
        </style>
    """
    st.markdown(button_styles, unsafe_allow_html=True)
def log_user_activity(username, action_type, action_details, entity_id=None):
    with sqlite3.connect('candidate_evaluation.db') as conn:
        try:
            c = conn.cursor()
            c.execute('''
                INSERT INTO user_activity 
                (username, action_type, action_details, entity_id)
                VALUES (?, ?, ?, ?)
            ''', (username, action_type, action_details, entity_id))
            conn.commit()
        except sqlite3.Error as e:
            st.error(f"Error logging activity: {e}")


def add_evaluation(emp_id, evaluator_id, eval_type, score, comments):
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    try:
        c.execute('''
            INSERT INTO evaluation_history 
            (emp_id, evaluated_by, evaluation_type, evaluation_date, score, comments)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
        ''', (emp_id, evaluator_id, eval_type, score, comments))
        conn.commit()
    finally:
        conn.close()
# Initialize SQLite database with proper check for existing database

def init_db():
    # Database configuration
    db_path = 'candidate_evaluation.db'
    
    # Create initial admin user data
    initial_admin = {
        'username': 'admin',
        'password': 'hashed_password',  # Remember to hash this
        'role': 'admin'
    }
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            reset_token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            used BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
                    # Add this table creation query:
        c.execute('''
            CREATE TABLE IF NOT EXISTS user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action_type TEXT,
                action_details TEXT,
                entity_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            
        ''')

            # Add this to your existing init_db() function
        c.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    logout_time TIMESTAMP,
                    session_duration INTEGER,
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            ''')
        
            # Create users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        
        # Create candidates table (your existing table)
        c.execute('''
            CREATE TABLE IF NOT EXISTS candidates (
                emp_id TEXT PRIMARY KEY,
                fullname TEXT,
                phone TEXT,
                skills TEXT,
                location TEXT,
                hands_on_skills TEXT,
                total_experience TEXT,
                grade TEXT,
                resume_data BLOB,
                resume_name TEXT,
                employer_id TEXT,
                interview_status TEXT,
                trial_start_date TEXT,
                trial_end_date TEXT,
                final_status TEXT,
                client_name TEXT,
                client_account TEXT,             
                comment TEXT,
                review TEXT,
                interviwed_by TEXT,               
                project_allocation TEXT,
                reject_account TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create activity_logs table for tracking
        c.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action_type TEXT,
                action_description TEXT,
                emp_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (emp_id) REFERENCES candidates(emp_id)
            )
        ''')
        
        # Create evaluation_history table
        c.execute('''
            CREATE TABLE IF NOT EXISTS evaluation_history (
                evaluation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                emp_id TEXT,
                evaluated_by INTEGER,
                evaluation_type TEXT,
                evaluation_date TIMESTAMP,
                score TEXT,
                comments TEXT,
                FOREIGN KEY (emp_id) REFERENCES candidates(emp_id),
                FOREIGN KEY (evaluated_by) REFERENCES users(user_id)
            )
        ''')

        conn.commit()
        
        # Verify tables were created
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = c.fetchall()
        print("Created tables:", [table[0] for table in tables])
        
        # Initialize admin user if not exists
        c.execute("SELECT username FROM users WHERE username=?", (initial_admin['username'],))
        if not c.fetchone():
            c.execute('''
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            ''', (initial_admin['username'], initial_admin['password'], initial_admin['role']))
            conn.commit()
            print("Admin user initialized")
            
        return True, "Database initialized successfully"
        
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"
        
    finally:
        if conn:
            conn.close()

def verify_db_connection():
    """Verify database connection and table existence"""
    try:
        conn = sqlite3.connect('candidate_evaluation.db')
        c = conn.cursor()
        
        # Check all required tables
        required_tables = ['users', 'candidates', 'activity_logs', 'evaluation_history']
        
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [table[0] for table in c.fetchall()]
        
        missing_tables = [table for table in required_tables if table not in existing_tables]
        
        if missing_tables:
            return False, f"Missing tables: {', '.join(missing_tables)}"
        
        return True, "Database verification successful"
        
    except sqlite3.Error as e:
        return False, f"Database verification failed: {str(e)}"
        
    finally:
        if conn:
            conn.close()


        
def validate_phone(phone):
    """Validate phone number format"""
    if not phone:
        return False
    cleaned_phone = phone.replace('-', '').replace('+', '').replace(' ', '')
    return cleaned_phone.isdigit() and len(cleaned_phone) >= 10
def validate_experience(experience):
    """Validate experience format"""
    if not experience:
        return False
    try:
        parts = experience.split()
        float(parts[0])
        return len(parts) >= 2
    except:
        return False
def validate_fields(required_fields):
    """Validates if all required fields are filled and properly formatted"""
    is_valid = True    
    for field_name, field_data in required_fields.items():
        value = field_data['value']
        rules = field_data['rules']        
        if rules.get('required', False):
            if value is None or (isinstance(value, str) and value.strip() == ''):
                st.warning(f"⚠️ {field_name} is required!")
                is_valid = False
                continue        
        if rules.get('is_phone', False) and value:
            if not validate_phone(value):
                st.warning(f"⚠️ {field_name} should be a valid phone number!")
                is_valid = False
        
        if rules.get('is_experience', False) and value:
            if not validate_experience(value):
                st.warning(f"⚠️ {field_name} should be in format '5 years' or '6 months'!")
                is_valid = False        
        if rules.get('is_file', False):
            if value is None:
                st.warning(f"⚠️ {field_name} is required!")
                is_valid = False
        if rules.get('is_text', False) and value:
            if len(value) > 500:
                st.warning(f"⚠️ {field_name} should not exceed 500 characters!")
                is_valid = False
        if rules.get('is_textarea', False) and value:
            if len(value) > 1000:
                st.warning(f"⚠️ {field_name} should not exceed 1000 characters!")
                is_valid = False
        if rules.get('is_dropdown', False) and value:
            if value == "Select":
                st.warning(f"⚠️ {field_name} is required!")
                is_valid = False
        if rules.get('is_date', False) and value:
            try:
                datetime.strptime(value, '%Y-%m-%d')
            except ValueError:
                st.warning(f"⚠️ {field_name} should be in format YYYY-MM-DD!")
                is_valid = False    
    return is_valid
# Initialize database
init_db()
@st.cache_data(ttl=3600)  # Cache for 1 hour
def get_candidate_data():
    conn = sqlite3.connect('candidate_evaluation.db')
    data = pd.read_sql_query("SELECT * FROM candidates", conn)
    conn.close()
    return data
def add_logout_button():
    if st.sidebar.button("Logout", key="logout_button"):
        # Log the logout activity first
        if st.session_state.get('username'):
            log_logout_session(st.session_state['username'])
            log_user_activity(
                st.session_state['username'], 
                "Logout", 
                "User logged out successfully"
            )
        
        # # Clear all session state variables
        # for key in list(st.session_state.keys()):
        #     del st.session_state[key]
        
        # Reset essential session states
        st.session_state['logged_in'] = False
        st.session_state['username'] = None
        st.session_state['role'] = None
        st.session_state['initialized'] = False
        
        st.rerun()

# Use context manager for database connections
def get_candidate_details():
    with sqlite3.connect('candidate_evaluation.db') as conn:
        try:
            query = '''
                SELECT emp_id, fullname, skills, hands_on_skills, 
                       total_experience, grade, phone, location, 
                       resume_name, employer_id
                FROM candidates 
                WHERE interview_status IS NULL OR interview_status = 'Pending'
            '''
            df = pd.read_sql_query(query, conn)
            return df
        except sqlite3.Error as e:
               st.error(f"Error fetching candidate details: {e}")
               return pd.DataFrame()

# After your imports and before your main app logic
def check_session():
    if 'logged_in' in st.session_state and st.session_state['logged_in']:
        return True
    return False

def check_session_validity():
    if st.session_state.get('logged_in', False):
        return True
    return False

            
def create_sample_excel():
    sample_data = {
        'emp_id': [
        '12345', '12346', '12347', '12348', '12349',
        '12350', '12351', '12352', '12353', '12354',
        '12355', '12356', '12357', '12358', '12359',
        '12360', '12361', '12362', '12363', '12364'
    ],
    'fullname': [
        'John Doe', 'Jane Smith', 'Mike Johnson', 'Sarah Williams', 'David Brown',
        'Emily Davis', 'James Wilson', 'Lisa Anderson', 'Robert Taylor', 'Mary Thomas',
        'Daniel White', 'Emma Garcia', 'Michael Lee', 'Jennifer Martin', 'William Clark',
        'Linda Rodriguez', 'Richard Moore', 'Susan Jackson', 'Joseph Martinez', 'Patricia Lewis'
    ],
    'phone': [
        '1234567890', '2345678901', '3456789012', '4567890123', '5678901234',
        '6789012345', '7890123456', '8901234567', '9012345678', '9123456789',
        '9234567890', '9345678901', '9456789012', '9567890123', '9678901234',
        '9789012345', '9890123456', '9901234567', '9012345679', '9123456780'
    ],
    'skills': [
        'Python, Java', 'JavaScript, React', 'Java, Spring Boot', 'Python, Django',
        'React, Node.js', 'Java, Hibernate', 'Python, Flask', 'Angular, TypeScript',
        'Python, Data Science', 'Java, Microservices', 'React, Redux', 'Python, AI',
        'Java, AWS', 'Full Stack, MERN', 'Python, Machine Learning', 'DevOps, Docker',
        'Java, Kubernetes', 'Python, TensorFlow', 'React Native, iOS', 'Android, Kotlin'
    ],
    'location': [
        'Bangalore', 'Hyderabad', 'Chennai', 'Mumbai', 'Pune',
        'Bangalore', 'Delhi', 'Hyderabad', 'Chennai', 'Mumbai',
        'Pune', 'Bangalore', 'Delhi', 'Hyderabad', 'Chennai',
        'Mumbai', 'Pune', 'Bangalore', 'Delhi', 'Hyderabad'
    ],
    'hands_on_skills': [
        'SQL, AWS', 'MongoDB, Azure', 'PostgreSQL, GCP', 'MySQL, AWS', 'Redis, Docker',
        'Oracle, Jenkins', 'DynamoDB, AWS', 'Cassandra, Kubernetes', 'SQL, Azure',
        'MongoDB, AWS', 'PostgreSQL, Docker', 'MySQL, GCP', 'Oracle, AWS',
        'SQL, Kubernetes', 'MongoDB, Jenkins', 'Redis, AWS', 'Cassandra, Azure',
        'PostgreSQL, Docker', 'MySQL, AWS', 'Oracle, GCP'
    ],
    'total_experience': [
        '5', '3', '7', '4', '6',
        '8', '2', '5', '4', '6',
        '3', '7', '5', '4', '8',
        '6', '3', '5', '4', '7'
    ],
    'grade': [
        'B', 'A', 'B+', 'A-', 'B',
        'A+', 'B', 'A', 'B+', 'A-',
        'B', 'A+', 'B', 'A', 'B+',
        'A-', 'B', 'A+', 'B', 'A'
    ],
    'employer_id': [
        '67890', '67891', '67892', '67893', '67894',
        '67895', '67896', '67897', '67898', '67899',
        '67900', '67901', '67902', '67903', '67904',
        '67905', '67906', '67907', '67908', '67909'
    ]
       
    }
    df = pd.DataFrame(sample_data)
    return df

def get_user_specific_data(username, table_name):
    """Get data specific to the logged-in user"""
    conn = sqlite3.connect('candidate_evaluation.db')
    try:
        if st.session_state['role'] == 'admin':
            # Admin sees all data
            query = f"SELECT * FROM {table_name}"
            df = pd.read_sql_query(query, conn)
        else:
            # Regular users see only their data
            query = f"SELECT * FROM {table_name} WHERE created_by = ? OR assigned_to = ?"
            df = pd.read_sql_query(query, conn, params=(username, username))
        return df
    finally:
        conn.close()

def show_associate_details():
    st.markdown("### 👤 Associate Details")
    
    # Get user-specific data
    df = get_user_specific_data(st.session_state['username'], 'candidates')
    
    if df.empty:
        st.info("No associate details available.")
        return
    
    # Display data in a formatted table
    st.dataframe(df)

    tab1, tab2,tab3  = st.tabs(["Manual Entry", "Bulk Upload" ,"sample upload"])
        
    with tab2:
            st.markdown("### Upload Excel File")
            st.markdown("""
            #### Instructions:
            1. Excel file must contain these columns: emp_id, fullname, phone, skills, location, hands_on_skills, total_experience, grade, employer_id
            2. Employee ID and phone numbers must be numeric
            3. Names should contain only alphabets
            """)
            
            excel_file = st.file_uploader("Upload Excel File", type=['xlsx', 'xls'])
            
            if excel_file is not None:
                if st.button("Process Excel File"):
                    with st.spinner('Processing Excel file...'):
                        success, message = process_excel_upload(excel_file)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
        # Add this in the tab2 section, before the file uploader
    with tab3:
            # Create download template button
            sample_df = create_sample_excel()
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                sample_df.to_excel(writer, index=False)
            st.download_button(
                label="📥 Download Sample Template",
                data=buffer.getvalue(),
                file_name="candidate_template.xlsx",
                mime="application/vnd.ms-excel"
            )
                
    with tab1:
            # Your existing manual entry form code goes here
            with st.form("candidate_form"):
                # ... (rest of your existing form code)
        
      
    # elif page ==  "👤 :blue[**Associate Details**]":
    #     st.markdown(" #### :blue[**Associate Details**]")
        
    #     with st.form("candidate_form"):
    #     # Basic Information
                col1, col2 ,col3 = st.columns(3)
                with col1:
                    emp_id = st.text_input("Employee ID")
                    #emp_id should take only numbers do not take alphabets
                    
                    if emp_id:
                        if emp_id and not emp_id.isdigit():
                            st.warning("Employee ID should be numeric")
                            st.toast("Employee ID should be numeric",icon="❌")
                    fullname = st.text_input("Full Name")
                    # Added full name input
                    if fullname:
                        if not fullname.replace(" ", "").isalpha():
                            st.warning("Full name should contain only alphabets")
                with col2:    
                    # Experience and Grade
                    total_experience = st.text_input("Total Experience (Years)")
                    grade = st.text_input("Grade")     
                with col3:
                    phone = st.text_input("Phone Number")
                    #put the limit that number should be 10 digits
                    if phone:
                        if  not phone.isdigit():
                            st.warning("Phone number should be numeric")
                    if phone:
                        if len(phone) != 10:
                            st.warning("Phone number should be 10 digits")
                    # Location with predefined options
                    location = st.selectbox(
                        "Location",
                        ["Bangalore", "Hyderabad", "Chennai", "Mumbai", "Delhi", "Pune", "Other"]
                    )
                    if location == "Other":
                        location = st.text_input("Specify Location")
                # Skills
                st.markdown("#### **:blue[Technical Skills]**")
                col3, col4 = st.columns(2)
                with col3:
                    skills = st.text_area("Primary Skills (comma-separated)")
                with col4:
                    hands_on_skills = st.text_area("Hands-on Skills (comma-separated)")
                # Resume Upload
                st.markdown("#### **:blue[Resume Upload (Optional)]**")
                resume_file = st.file_uploader("Upload Resume", type=['pdf', 'docx', 'doc'])
                # Associate Details data filled By
                st.markdown("#### **:blue[Associate Details Filled By]**")
            
            
                employer_id = st.text_input("Employer ID")
            
                if employer_id:
                    if employer_id and not employer_id.isdigit():
                        st.warning("Employee ID should be numeric")
                        st.toast("Employee ID should be numeric", icon="❌")
                    
                fields_to_validate = {
                "Employee ID": {
                    "value": emp_id,
                    "rules": {"required": True}
                },
                "Full Name": {
                    "value": fullname,
                    "rules": {"required": True}
                },
                "Phone Number": {
                    "value": phone,
                    "rules": {"required": True, "is_phone": True}
                },
                "Skills": {
                    "value": skills,
                    "rules": {"required": True}
                },
                "Location": {
                    "value": location,
                    "rules": {"required": True}
                },
                "Hands-on Skills": {
                    "value": hands_on_skills,
                    "rules": {"required": True}
                },
                "Total Experience": {
                    "value": total_experience,
                    "rules": {"required": True, "is_experience": True}
                },
                # "Resume": {
                #     "value": resume_file,
                #     "rules": {"required": True, "is_file": True}
                # },
                "Grade": {
                    "value": grade,
                    "rules": {"required": True}
                
                },
                "Employer ID": {
                    "value": employer_id,
                    "rules": {"required": True}
                }
            }
                
        
                submitted = st.form_submit_button("Submit")
            if submitted:        
                if validate_fields(fields_to_validate):
                    try:
                        interview_status = "Pending"
                        conn = sqlite3.connect('candidate_evaluation.db')
                        c = conn.cursor()
                        if resume_file:
                            resume_data = resume_file.read()
                            resume_name = resume_file.name
                        else:
                            resume_data = None
                            resume_name = None
                        c.execute('''
                            INSERT INTO candidates (
                                emp_id, fullname, phone, skills, location, hands_on_skills, 
                                total_experience, grade, resume_data, resume_name, employer_id,interview_status
                            
                            )
                            VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?)
                        ''', (
                            emp_id, fullname, phone, skills, location, hands_on_skills,
                            str(total_experience), grade, resume_data, resume_name,employer_id,interview_status))
                          # Log the activity
                        log_user_activity(
                            username=st.session_state.username,  # Store username in session state after login
                            action_type="ADD_CANDIDATE",
                            action_details=f"Added candidate: {fullname}",
                            entity_id=emp_id
                        )
                        st.success("Candidate information submitted successfully!", icon="✅")
                        conn.commit()
                        st.success("Candidate information submitted successfully!",icon="✅")
                        st.toast("Candidate information submitted successfully!", icon="✅")
                    except sqlite3.IntegrityError:
                        st.error("❌ Employee ID already exists!")
                        #st.error("Employee ID already exists!")
                        st.toast("Employee ID already exists!", icon="❌")
                    # except Exception as e:
                    #     st.error(f"❌ An error occurred: {str(e)}")
                    #     st.toast("An error occurred!", icon="❌")
                    finally:
                        conn.close()
                else:
                    st.error("❌ Please fix the validation errors before submitting.")
                    #st.warning("Please fill all required fields!")
                    st.toast("Please fill all required fields!", icon="❌")

def show_technical_evaluation():
    
    st.markdown("### 💻 Technical Evaluation")
    
    # Get user-specific technical evaluations
    df = get_user_specific_data(st.session_state['username'], 'evaluation_history')
    df = df[df['evaluation_type'] == 'technical']
    
    if df.empty:
        st.info("No technical evaluations available.")
        return
    
    st.dataframe(df)

def show_project_evaluation():
    st.markdown("### 📋 Project Evaluation")
    
    # Get user-specific project evaluations
    df = get_user_specific_data(st.session_state['username'], 'evaluation_history')
    df = df[df['evaluation_type'] == 'project']
    
    if df.empty:
        st.info("No project evaluations available.")
        return
    
    st.dataframe(df)

def show_client_evaluation():
    st.markdown("### 🤝 Client Evaluation")
    
    # Get user-specific client evaluations
    df = get_user_specific_data(st.session_state['username'], 'evaluation_history')
    df = df[df['evaluation_type'] == 'client']
    
    if df.empty:
        st.info("No client evaluations available.")
        return
    
    st.dataframe(df)

def show_reports():
    st.markdown("### 📊 Reports")
    
    # Get user-specific reports data
    candidates_df = get_user_specific_data(st.session_state['username'], 'candidates')
    evaluations_df = get_user_specific_data(st.session_state['username'], 'evaluation_history')
    
    if candidates_df.empty and evaluations_df.empty:
        st.info("No report data available.")
        return
    
    # Show relevant metrics and visualizations
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Candidates", len(candidates_df))
    with col2:
        st.metric("Evaluations Completed", len(evaluations_df))
    with col3:
        avg_score = evaluations_df['score'].mean() if not evaluations_df.empty else 0
        st.metric("Average Score", f"{avg_score:.2f}")



# Add this to your database initialization
def modify_database_tables():
    conn = sqlite3.connect('candidate_evaluation.db')
    c = conn.cursor()
    
    # Add new columns to track user assignments
    try:
        c.execute('''
            ALTER TABLE candidates 
            ADD COLUMN created_by TEXT;
        ''')
        c.execute('''
            ALTER TABLE candidates 
            ADD COLUMN assigned_to TEXT;
        ''')
        
        c.execute('''
            ALTER TABLE evaluation_history 
            ADD COLUMN created_by TEXT;
        ''')
        c.execute('''
            ALTER TABLE evaluation_history 
            ADD COLUMN assigned_to TEXT;
        ''')
        
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Columns might already exist
    finally:
        conn.close()

# Call this function during initialization
modify_database_tables()
# Modify your main navigation to include these pages
def main_navigation():
    st.sidebar.title("Navigation")
    
    page = st.sidebar.selectbox(
        "Select a page",
        ["Associate Details", "Technical Evaluation", 
         "Project Evaluation", "Client Evaluation", "Reports"]
    )
    
    if page == "Associate Details":
        show_associate_details()
    elif page == "Technical Evaluation":
        show_technical_evaluation()
    elif page == "Project Evaluation":
        show_project_evaluation()
    elif page == "Client Evaluation":
        show_client_evaluation()
    elif page == "Reports":
        show_reports()
        
# Update your login success handler to include the navigation
def login_success(username, role):
    st.session_state['logged_in'] = True
    st.session_state['username'] = username
    st.session_state['role'] = role
    st.session_state['initialized'] = True
    
    # Log the login activity
    log_user_activity(username, "Login", "User logged in successfully")
    
    # Show the navigation
    main_navigation()


def main():
      # Check if user is logged in
    if not check_session():
        login_page()
        st.stop()
        
  

     # Initialize database before use
    success, message = init_db()
    if not success:
        st.error(message)
        return
   
    st.sidebar.write(f"👤Role : {st.session_state['role'].title()}")
    st.sidebar.write(f"🧑‍💻Name : {st.session_state['username']}")

    #st.sidebar.write("🧑‍💻" + st.session_state.role['role'])
    # Role-based navigation options
    if st.session_state['role'] == 'admin':
    # Sidebar for navigation
        page = st.sidebar.radio(
        "***:rainbow[Select Page]***",
        [
            "🏠 :blue[**Home**]",
            "👤 :blue[**Associate Details**]",
            "💻 :blue[**Technical Evaluation**]", 
            "📋 :blue[**Project Evaluation**]",
            "🤝 :blue[**Client Evaluation**]",
            "📊 :blue[**Reports**]",
            "📈 :blue[**Login Analytics**]"  
            

            
        ]
    )
    else:
        page = st.sidebar.radio(
            "***:rainbow[Select Page]***",
            [
                "🏠 :blue[**Home**]",
                "👤 :blue[**Associate Details**]",
                "💻 :blue[**Technical Evaluation**]",
                "📋 :blue[**Project Evaluation**]",
                "🤝 :blue[**Client Evaluation**]",
                "📊 :blue[**Reports**]",               
                "📈 :blue[**My Login History**]"  

            ]
            
            
     
            
        )
    # Add logout button to sidebar
    add_logout_button()
        # Create a footer container
    footer = st.sidebar.container()
    
    with footer:
            # Add some padding to the footer
            st.markdown("<br>", unsafe_allow_html=True)
             #Add some spacing before the footer
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            with footer:
                # Center-align the footer text
                st.markdown(
                    """
                    <div>
                        <p></p>
                        <p style='font-size: 0.7em;'> © 2025 TalentFlow. All rights reserved.</p>
                    </div>
                    """, 
                    unsafe_allow_html=True
                )
    st.markdown("""
    <style>
    @keyframes bounce {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-20px); }
    }
    .bounce {
        animation: bounce 2s infinite;
    }
    .dashboard-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            padding: 20px;
        }    
        .dashboard-section {
            background-color: Black;
            border: 5px solid #ccc;
            padding: 20px;
            border-radius: 30px;
            box-shadow: #fff000;
            flex: 1;
            min-width: 250px;
            title: {
                color: #1f4788;
                font-size: 1.5em;
                margin-bottom: 10px;
                font-weight: bold;
            
        }
        .dashboard-section h4 {
            color: #1f4788;
            margin-bottom: 15px;
        }
        
        .dashboard-section ul {
            list-style: none;
            padding-left: 0;
        }
        
        .dashboard-section li {
            margin-bottom: 8px;
            color: #666;
        }
    
    
    </style>
    """, unsafe_allow_html=True)
    if page == "🏠 :blue[**Home**]":
        st.markdown("""
    <h1 class='bounce'  style='text-align: center;background: linear-gradient(
        to right,
        red,
        orange,
        yellow,
        green,
        blue,
        indigo,
        violet
    ); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
   Welcome to TalentFlow!
    </h1>
""", unsafe_allow_html=True)

        #st.markdown("<h1 class='bounce' style='text-align: center; color: rgb(49, 49, 49);' >Welcome to TalentFlow!</h1>",unsafe_allow_html=True)
        #st.info("Welcome to TalentFlow - Your Partner in Talent Acquisition and Management")
        #st.title("**:rainbow[TalentFlow]**", anchor=False, help="***Your Partner in Talent Acquisition and Management***")

        st.markdown(
            """
            <div style='text-align: left;'>
                <p style='font-size: 1.2em;color :#999cf' >
                    <strong>TalentFlow</strong>  help you to find out the  <strong>Right Candidates</strong> for your <strong>Projects</strong> and <strong>Clients</strong>.
                </p>
            </div>
            """,
            unsafe_allow_html=True)
        #st.image("images/LPP.jpg", width=750)

        # # Create three columns
        # col1, col2 = st.columns(2)        
        # with col1:
        #     st.markdown("""                
        #         <div class="dashboard-section">
        #             <h4>👤 Associate Details</h4>
        #             <ul>
        #                 <li>Manage associate profiles</li>
        #                 <li>Track personal information</li>
        #                 <li>Update associate status</li>
        #             </ul>
        #         </div>
        #     """, unsafe_allow_html=True)
        #     st.markdown("<br>", unsafe_allow_html=True)
        #     st.markdown("""
        #         <div class="dashboard-section">
        #             <h4>💻 Technical Evaluation</h4>
        #             <ul>
        #                 <li>Assess technical skills</li>
        #                 <li>Track technical growth</li>
        #                 <li>Record certifications</li>
        #             </ul>
        #         </div>
        #     """, unsafe_allow_html=True)
            
        #     st.markdown("<br>", unsafe_allow_html=True)
        #     st.markdown("""
        #         <div class="dashboard-section">
        #             <h4>📋 Project Evaluation</h4>
        #             <ul>
        #                 <li>Monitor performance</li>
        #                 <li>Track assignments</li>
        #                 <li>Evaluate skills</li>
        #             </ul>
        #         </div>
        #     """, unsafe_allow_html=True)
        # st.markdown("<br>", unsafe_allow_html=True)
        # with col2:
        #     st.markdown("""
        #         <div class="dashboard-section">
        #             <h4>🤝 Client Evaluation</h4>
        #             <ul>
        #                 <li>Record client feedback</li>
        #                 <li>Track satisfaction</li>
        #                 <li>Monitor relationships</li>
        #             </ul>
        #         </div>
        #     """, unsafe_allow_html=True)
        #     st.markdown("<br>", unsafe_allow_html=True)
        #     st.markdown("""
        #         <div class="dashboard-section">
        #             <h4>📊 Reports</h4>
        #             <ul>
        #                 <li>Generate reports</li>
        #                 <li>View analytics</li>
        #                 <li>Export data</li>
        #             </ul>
        #         </div>
        #     """, unsafe_allow_html=True)
        #     st.markdown("<br>", unsafe_allow_html=True)
        #     st.markdown("""
        #         <div class="dashboard-section">
        #             <h4>📝Data</h4>
        #             <ul>
        #                 <li>Export notes</li>
        #                 <li>Import notes</li>
        #                 <li>Interview Q/A Data</li>
        #             </ul>
        #         </div>
        #     """, unsafe_allow_html=True)
            

    elif page == "👤 :blue[**Associate Details**]":
        st.markdown(" #### :blue[**Associate Details**]")
        
        # Add tabs for manual entry and bulk upload
        tab1, tab2,tab3  = st.tabs(["Manual Entry", "Bulk Upload" ,"sample upload"])
        
        with tab2:
            st.markdown("### Upload Excel File")
            st.markdown("""
            #### Instructions:
            1. Excel file must contain these columns: emp_id, fullname, phone, skills, location, hands_on_skills, total_experience, grade, employer_id
            2. Employee ID and phone numbers must be numeric
            3. Names should contain only alphabets
            """)
            
            excel_file = st.file_uploader("Upload Excel File", type=['xlsx', 'xls'])
            
            if excel_file is not None:
                if st.button("Process Excel File"):
                    with st.spinner('Processing Excel file...'):
                        success, message = process_excel_upload(excel_file)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
        # Add this in the tab2 section, before the file uploader
        with tab3:
            # Create download template button
            sample_df = create_sample_excel()
            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                sample_df.to_excel(writer, index=False)
            st.download_button(
                label="📥 Download Sample Template",
                data=buffer.getvalue(),
                file_name="candidate_template.xlsx",
                mime="application/vnd.ms-excel"
            )
                
        with tab1:
            # Your existing manual entry form code goes here
            with st.form("candidate_form"):
                # ... (rest of your existing form code)
        
      
    # elif page ==  "👤 :blue[**Associate Details**]":
    #     st.markdown(" #### :blue[**Associate Details**]")
        
    #     with st.form("candidate_form"):
    #     # Basic Information
                col1, col2 ,col3 = st.columns(3)
                with col1:
                    emp_id = st.text_input("Employee ID")
                    #emp_id should take only numbers do not take alphabets
                    
                    if emp_id:
                        if emp_id and not emp_id.isdigit():
                            st.warning("Employee ID should be numeric")
                            st.toast("Employee ID should be numeric",icon="❌")
                    fullname = st.text_input("Full Name")
                    # Added full name input
                    if fullname:
                        if not fullname.replace(" ", "").isalpha():
                            st.warning("Full name should contain only alphabets")
                with col2:    
                    # Experience and Grade
                    total_experience = st.text_input("Total Experience (Years)")
                    grade = st.text_input("Grade")     
                with col3:
                    phone = st.text_input("Phone Number")
                    #put the limit that number should be 10 digits
                    if phone:
                        if  not phone.isdigit():
                            st.warning("Phone number should be numeric")
                    if phone:
                        if len(phone) != 10:
                            st.warning("Phone number should be 10 digits")
                    # Location with predefined options
                    location = st.selectbox(
                        "Location",
                        ["Bangalore", "Hyderabad", "Chennai", "Mumbai", "Delhi", "Pune", "Other"]
                    )
                    if location == "Other":
                        location = st.text_input("Specify Location")
                # Skills
                st.markdown("#### **:blue[Technical Skills]**")
                col3, col4 = st.columns(2)
                with col3:
                    skills = st.text_area("Primary Skills (comma-separated)")
                with col4:
                    hands_on_skills = st.text_area("Hands-on Skills (comma-separated)")
                # Resume Upload
                st.markdown("#### **:blue[Resume Upload (Optional)]**")
                resume_file = st.file_uploader("Upload Resume", type=['pdf', 'docx', 'doc'])
                # Associate Details data filled By
                st.markdown("#### **:blue[Associate Details Filled By]**")
            
            
                employer_id = st.text_input("Employer ID")
            
                if employer_id:
                    if employer_id and not employer_id.isdigit():
                        st.warning("Employee ID should be numeric")
                        st.toast("Employee ID should be numeric", icon="❌")
                    
                fields_to_validate = {
                "Employee ID": {
                    "value": emp_id,
                    "rules": {"required": True}
                },
                "Full Name": {
                    "value": fullname,
                    "rules": {"required": True}
                },
                "Phone Number": {
                    "value": phone,
                    "rules": {"required": True, "is_phone": True}
                },
                "Skills": {
                    "value": skills,
                    "rules": {"required": True}
                },
                "Location": {
                    "value": location,
                    "rules": {"required": True}
                },
                "Hands-on Skills": {
                    "value": hands_on_skills,
                    "rules": {"required": True}
                },
                "Total Experience": {
                    "value": total_experience,
                    "rules": {"required": True, "is_experience": True}
                },
                # "Resume": {
                #     "value": resume_file,
                #     "rules": {"required": True, "is_file": True}
                # },
                "Grade": {
                    "value": grade,
                    "rules": {"required": True}
                
                },
                "Employer ID": {
                    "value": employer_id,
                    "rules": {"required": True}
                }
            }
                
        
                submitted = st.form_submit_button("Submit")
            if submitted:        
                if validate_fields(fields_to_validate):
                    try:
                        interview_status = "Pending"
                        conn = sqlite3.connect('candidate_evaluation.db')
                        c = conn.cursor()
                        if resume_file:
                            resume_data = resume_file.read()
                            resume_name = resume_file.name
                        else:
                            resume_data = None
                            resume_name = None
                        c.execute('''
                            INSERT INTO candidates (
                                emp_id, fullname, phone, skills, location, hands_on_skills, 
                                total_experience, grade, resume_data, resume_name, employer_id,interview_status
                            
                            )
                            VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?)
                        ''', (
                            emp_id, fullname, phone, skills, location, hands_on_skills,
                            str(total_experience), grade, resume_data, resume_name,employer_id,interview_status))
                          # Log the activity
                        log_user_activity(
                            username=st.session_state.username,  # Store username in session state after login
                            action_type="ADD_CANDIDATE",
                            action_details=f"Added candidate: {fullname}",
                            entity_id=emp_id
                        )
                        st.success("Candidate information submitted successfully!", icon="✅")
                        conn.commit()
                        st.success("Candidate information submitted successfully!",icon="✅")
                        st.toast("Candidate information submitted successfully!", icon="✅")
                    except sqlite3.IntegrityError:
                        st.error("❌ Employee ID already exists!")
                        #st.error("Employee ID already exists!")
                        st.toast("Employee ID already exists!", icon="❌")
                    # except Exception as e:
                    #     st.error(f"❌ An error occurred: {str(e)}")
                    #     st.toast("An error occurred!", icon="❌")
                    finally:
                        conn.close()
                else:
                    st.error("❌ Please fix the validation errors before submitting.")
                    #st.warning("Please fill all required fields!")
                    st.toast("Please fill all required fields!", icon="❌")
   
    
    elif page == "💻 :blue[**Technical Evaluation**]":
        st.markdown("#### :blue[**Technical Evaluation**]")
        try:
            conn = sqlite3.connect('candidate_evaluation.db')
            df = pd.read_sql_query("""
                SELECT emp_id, fullname,phone, skills, location, hands_on_skills, 
                    total_experience, grade ,employer_id
                FROM candidates 
                WHERE interview_status IS NULL OR interview_status = 'Pending'
            """, conn)
            df = df.sort_values(by='emp_id', ascending=False)
            if df.empty:
                st.info("No candidates pending for technical evaluation")
                #submit_button = st.button("Submit Evaluation")

            if not df.empty:
                selected_emp = st.selectbox("Select Employee ID", df['emp_id'])
                candidate_info = df[df['emp_id'] == selected_emp].iloc[0]
                
                # Display candidate information in columns
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.markdown("#### :blue[**Basic Details**]")
                    st.write("Employee ID:", selected_emp)
                    st.write("Full Name:", candidate_info['fullname'])
                    st.write("Phone Number:", candidate_info['phone'])
                with col2:
                    st.markdown("#### :blue[**Skills**] ")
                    st.write("Total Experience:", candidate_info['total_experience'], "years")
                    st.write("Primary Skills:", candidate_info['skills'])
                    st.write("Hands-on Skills:", candidate_info['hands_on_skills'])
                with col3:
                    st.markdown("#### :blue[**Other Info**]")
                    st.write("Grade:", candidate_info['grade'])
                    st.write("Location:", candidate_info['location'])
                    st.write("Employer ID:", candidate_info['employer_id'])

                # Get resume if available
                conn = sqlite3.connect('candidate_evaluation.db')
                c = conn.cursor()
                c.execute("SELECT resume_data, resume_name FROM candidates WHERE emp_id=?", (selected_emp,))
                resume_info = c.fetchone()
                conn.close()

                if resume_info and resume_info[0]:
                    st.download_button(
                        label="Download Resume",
                        data=resume_info[0],
                        file_name=resume_info[1],
                        mime="application/octet-stream"
                    )

                st.markdown("#### :blue[**Evaluation**]")
                status = st.radio("Interview Status", ["Selected", "Rejected"])

                if status == "Selected":
                    review = st.text_area("Review (Mention Reason for Selection)")
                    interviwed_by = st.text_input("Interviewed By (Employ ID)")
                    if interviwed_by and not interviwed_by.isdigit():
                        st.warning("Employee ID should be numeric")

                elif status == "Rejected":
                    comment = st.text_area("Comment (REASON FOR REJECTION AND KEY EXPECTATIONS THAT THE ASSOCIATE DID NOT MEET)")
                    interviwed_by = st.text_input("Interviewed By (Employ ID)")
                    if interviwed_by and not interviwed_by.isdigit():
                        st.warning("Employee ID should be numeric")

                submit_button = st.button("Submit")

                if submit_button:
                    if not status:
                        st.error("Please select an interview status")
                        st.toast("Please select an interview status", icon="❌")
                    elif status == "Selected" and (not review or not interviwed_by):
                        st.error("Please fill all required fields")
                        st.toast("Please fill all required fields", icon="❌")
                    elif status == "Rejected" and (not comment or not interviwed_by):
                        st.error("Please fill all required fields")
                        st.toast("Please fill all required fields", icon="❌")
                    elif not interviwed_by.isdigit():
                        st.error("Employee ID should be numeric")
                        st.toast("Employee ID should be numeric", icon="❌")
                    else:
                        conn = sqlite3.connect('candidate_evaluation.db')
                        c = conn.cursor()
                        try:
                            if status == "Selected":
                                trial_start = datetime.now()
                                trial_end = trial_start + timedelta(days=7)
                                c.execute('''
                                    UPDATE candidates 
                                    SET interview_status=?, trial_start_date=?, trial_end_date=?, interviwed_by=?, review=?
                                    WHERE emp_id=?
                                ''', (status, trial_start.strftime('%Y-%m-%d'), trial_end.strftime('%Y-%m-%d'),
                                    interviwed_by, review, selected_emp))
                            else:  # Rejected
                                c.execute('''
                                    UPDATE candidates
                                    SET interview_status=?, comment=?, interviwed_by=?
                                    WHERE emp_id=?
                                ''', (status, comment, interviwed_by, selected_emp))

                            conn.commit()
                            st.success(f"Candidate {selected_emp} has been {status}", icon="✅")
                            st.toast(f"Candidate {selected_emp} has been {status}", icon="✅")
                            #put some sleep
                            time.sleep(1)
                            st.rerun()
                        except sqlite3.Error as e:
                            st.error(f"Database error: {str(e)}")
                        finally:
                            conn.close()

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

        finally:
            if 'conn' in locals():
                conn.close()
             
    elif page ==  "📋 :blue[**Project Evaluation**]":
        st.markdown("#### :blue[**Project Evaluation**]")
        
        conn = sqlite3.connect('candidate_evaluation.db')
        df = pd.read_sql_query("""
            SELECT emp_id, fullname,phone, skills, location, hands_on_skills, total_experience, grade,
                   trial_start_date, trial_end_date ,employer_id,review,comment,interviwed_by,client_name
            FROM candidates 
            WHERE interview_status='Selected' AND final_status IS NULL
        """, conn)
        conn.close()
        if not df.empty:
            selected_emp = st.selectbox("Select Employee ID", df['emp_id'])
            candidate_info = df[df['emp_id'] == selected_emp].iloc[0]
            col1, col2,col3,col4 = st.columns(4)
            with col1:
                st.markdown("#### :blue[**Basic Details**]")
                st.write("Employee ID:", selected_emp)
                st.write("Full Name:", candidate_info['fullname'])
                st.write("Total Experience:", candidate_info['total_experience'], "years")
                st.write("Phone Number:", candidate_info['phone'])    
            with col2:
                st.markdown("#### :blue[**Other Info**]")   
                st.write("Grade:", candidate_info['grade'])
                st.write("Location:", candidate_info['location'])
                st.write("Employer ID:", candidate_info['employer_id'])
                st.write("Interviewed By:", candidate_info['interviwed_by'])
            with col3:
                st.markdown("#### :blue[**Skills**]")  
                st.write("Primary Skills:", candidate_info['skills'])
                st.write("Hands-on Skills:", candidate_info['hands_on_skills'])
                st.write("Review:", candidate_info['review'])
                #st.write("Comment:", candidate_info['comment'])   
            with col4:
                st.markdown("#### :blue[**Trial Period**]")   
                st.write("Start Date:", candidate_info['trial_start_date'])
                st.write("End Date:", candidate_info['trial_end_date'])
            client_name = None
            client_account = None
            reject_account = None
            final_status = st.radio(":blue[**Final Status**]", ["Selected", "Rejected"])
            client_name = st.text_input("Project Allocator (Employ ID)")
            
            if client_name:
                if not client_name.isdigit():
                    st.warning("Project Allocator should contain only Numbers")
                    st.toast("Project Allocator should contain only Numbers", icon="❌")
                # elif len(client_name) != 6:
                #     st.warning("Project Allocator should be 6 digits long")
                #     st.toast("Project Allocator should be 6 digits long", icon="❌")
            if final_status == "Selected":
                client_account = st.text_input("Assign Client Account")
                # #is empty
                # client_accountempty = not client_account
                # if client_accountempty:
                #     st.warning("Please enter client account")
                #     st.toast("Please enter client account", icon="❌")
            else:
                reject_account = st.text_area("Reason for Rejection")
                # #is empty
                # reject_accountempty = not reject_account
                # if reject_accountempty:
                #     st.warning("Please enter reason for rejection")
                #     st.toast("Please enter reason for rejection", icon="❌")
            if st.button("Submit Final Status"):
                if final_status == "Selected" and (not client_account or not client_name):
                    st.error("Please fill all required fields")
                    st.toast("Please fill all required fields", icon="❌")
                    return
                elif final_status == "Rejected" and not reject_account:
                    st.error("Please fill all required fields")
                    st.toast("Please fill all required fields", icon="❌")
                    return
                conn = sqlite3.connect('candidate_evaluation.db')
                c = conn.cursor()
                if client_name and not client_name.isdigit():
                    st.warning("Project Allocator should contain only Numbers")
                    st.toast("Project Allocator should contain only Numbers", icon="❌")
                    return
                if final_status == "Selected" and client_account and client_name:
                    c.execute('''
                        UPDATE candidates 
                        SET final_status=?, client_account=? ,client_name=?
                        WHERE emp_id=?
                    ''', (final_status, client_account,client_name, selected_emp))
                    success_msg = f"Candidate {selected_emp} has been Selected and assigned to {client_account} by {client_name}"             
                    st.success(success_msg,icon="✅")
                    st.toast(success_msg, icon="✅")
                    time.sleep(2)  # Wait for 2 seconds
                    #st.rerun() 
                elif final_status == "Rejected" and reject_account:
                    c.execute('''
                        UPDATE candidates
                        SET final_status=?, reject_account=?,client_name=?
                        WHERE emp_id=?
                    ''', (final_status, reject_account, client_name,selected_emp))
                    success_msg = f"Candidate {selected_emp} has been rejected by {client_name}"
                    st.success(success_msg,icon="✅")
                    st.toast(success_msg, icon="✅")
                    time.sleep(2)
                    #st.rerun()  
                                      
                conn.commit()
                conn.close()            
        else:
            st.info("No candidates in trial period")    
    elif page == "🤝 :blue[**Client Evaluation**]":
        st.markdown("#### :blue[**Client Evaluation**]")
        #show only slected candidates
        st.info("***:rainbow[Only Selected Candidates are shown]***")
        
        
        conn = sqlite3.connect('candidate_evaluation.db')
        df = pd.read_sql_query("""
            SELECT emp_id, fullname,phone, skills, location, hands_on_skills, total_experience, grade,
                   trial_start_date, trial_end_date ,employer_id,review,interviwed_by,client_name,client_account,final_status
            FROM candidates
            WHERE final_status='Selected'
        """, conn)
        conn.close()  
        
               # Add search functionality
        search_term = st.text_input("Search by name or skills:")
        if search_term:
            df = df[df['fullname'].str.contains(search_term, case=False) | 
                    df['skills'].str.contains(search_term, case=False)]

    

        #st.dataframe(df, hide_index=True) 
               # Show basic statistics
	    
   
           # Add column configuration
        #st.subheader("Candidate Details")
        st.header("**:rainbow[Statistics]**")    
        st.metric("Total Candidates", len(df))
        column_config = {
        'emp_id': 'Employee ID',
        'fullname': 'Full Name',
        'phone': st.column_config.NumberColumn('Phone Number'),
        'trial_start_date': st.column_config.DateColumn('Trial Start'),
        'trial_end_date': st.column_config.DateColumn('Trial End'),
        'total_experience': st.column_config.NumberColumn('Experience (Years)', format="%.1f"),
        'skills': 'Primary Skills',
        'hands_on_skills': 'Hands-on Skills',
        'grade': 'Grade',
        'location': 'Location',
        'employer_id': 'Employer ID',
        'interviwed_by': 'Interviewed By',
        'review': 'Review',
        
        'client_name': 'Project Allocator',
        'client_account': 'Client Account',
        'final_status': 'Final Status'
    }

    # Display the dataframe with enhanced formatting
        st.dataframe(
        df,
        hide_index=True,
        column_config=column_config,
        use_container_width=True
    )

        
        #st.bar_chart(df)
    
        
    elif page =="📊 :blue[**Reports**]":
        st.markdown("### :blue[**Candidate Status Reports**]")       
        report_type = st.selectbox("Select Report Type",["All Candidates",  "Selected", "Rejected" ,"Pending" ,"In Trail"])
        conn = sqlite3.connect('candidate_evaluation.db')
         # Query based on report type
        if report_type == "All Candidates":
            query = """
                SELECT emp_id, employer_id, fullname, phone, location,
           skills, hands_on_skills, total_experience, grade,
           interview_status, trial_start_date, trial_end_date, final_status,
           client_name, client_account, reject_account,
           review, comment
                FROM candidates
            """
        elif report_type == "Pending":
            query = """
                SELECT emp_id, fullname, phone, skills, location, 
                    hands_on_skills, total_experience, grade,
                    interview_status, trial_start_date, trial_end_date,
                    final_status, client_account , reject_account,employer_id,client_name,review,comment
                FROM candidates 
                WHERE interview_status='Pending'
            """
        elif report_type == "In Trial":
            query = """
                SELECT emp_id, employer_id, fullname, phone, location,
           skills, hands_on_skills, total_experience, grade,
           interview_status, trial_start_date, trial_end_date, final_status,
           client_name, client_account, reject_account,
           review, comment
                FROM candidates 
                WHERE interview_status='In Trial'
            """
        elif report_type == "Selected":
            query = """
                SELECT emp_id, employer_id, fullname, phone, location,
           skills, hands_on_skills, total_experience, grade,
           interview_status, trial_start_date, trial_end_date, final_status,
           client_name, client_account, reject_account,
           review, comment
                FROM candidates 
                WHERE final_status='Selected'
            """
        else:  # Rejected
            query = """
                SELECT emp_id, employer_id, fullname, phone, location,
           skills, hands_on_skills, total_experience, grade,
           interview_status, trial_start_date, trial_end_date, final_status,
           client_name, client_account, reject_account,
           review, comment
                FROM candidates 
                WHERE final_status='Rejected'
            """                
        df = pd.read_sql_query(query, conn)
                # Add status-based metrics with colors
        if 'final_status' in df.columns:
            col1, col2, col3 = st.columns(3)
            
            selected = len(df[df['final_status'].str.lower() == 'selected'].fillna(0))
            rejected = len(df[df['final_status'].str.lower() == 'rejected'].fillna(0))
            pending = len(df[df['final_status'].isnull() | (df['final_status'] == '')].fillna(0))
            
            with col1:
                st.markdown(f"""
                    <div style="
                        padding: 10px;
                        border-radius: 5px;
                        background-color: rgba(40, 167, 69, 0.2);
                        border: 2px solid #28a745;
                        text-align: center;">
                        <h4 style="color: #28a745;">Selected</h4>
                        <h2 style="color: #28a745;">{selected}</h2>
                    </div>
                    """, unsafe_allow_html=True)
                
            with col2:
                st.markdown(f"""
                    <div style="
                        padding: 10px;
                        border-radius: 5px;
                        background-color: rgba(220, 53, 69, 0.2);
                        border: 2px solid #dc3545;
                        text-align: center;">
                        <h4 style="color: #dc3545;">Rejected</h4>
                        <h2 style="color: #dc3545;">{rejected}</h2>
                    </div>
                    """, unsafe_allow_html=True)
                
            with col3:
                st.markdown(f"""
                    <div style="
                        padding: 10px;
                        border-radius: 5px;
                        background-color: rgba(255, 193, 7, 0.2);
                        border: 2px solid #ffc107;
                        text-align: center;">
                        <h4 style="color: #ffc107;">Pending</h4>
                        <h2 style="color: #ffc107;">{pending}</h2>
                    </div>
                    """, unsafe_allow_html=True)
            st.write("")
            st.write("")
        conn.close()        
        if not df.empty:
            # Remove resume_data from display
            if 'resume_data' in df.columns:
                df = df.drop('resume_data', axis=1)
              # Define the style function for the entire row and make text bold           
            def style_dataframe(df):
                def highlight_rows(row):
                    if row['final_status'] == 'Selected':
                        return ['background-color: #2ECC71'] * len(row)  # Emerald Green
                    elif row['final_status'] == 'Rejected':
                        return ['background-color: #E74C3C'] * len(row)  # Darker Red
                    elif row['interview_status'] == 'In Trial':
                        return ['background-color: #3498DB'] * len(row)  # Darker Blue
                    elif row['interview_status'] == 'Pending':
                        return ['background-color: #F1C40F'] * len(row)  # Darker Yellow
                    # elif row['interview_status'] == 'Selected':
                    #     return ['background-color: #2ecc71'] * len(row)  # Darker Purple
                    # elif row['interview_status'] == 'Rejected':
                    #     return ['background-color: #E74c3c'] * len(row)  # Darker Orange
                    elif row['final_status'] == 'Rejected' or row['interview_status'] == 'Rejected':  # Check both statuses
                        return ['background-color: #E74C3C'] * len(row)  # Darker Red
                    else:
                        return [''] * len(row)
                return df.style.apply(highlight_rows, axis=1)
            # Apply styling
            styled_df = style_dataframe(df)
            # Display the report type and dataframe
            st.write(f"{report_type}:")
            st.dataframe(styled_df, use_container_width=True)           
            col1 ,col2 =st.columns(2)
            with col1:
                csv = df.to_csv(index=False)
                CSV_Butten_clicked = st.download_button(
                    label="Download Report as CSV",
                    data=csv,
                    file_name=f"candidate_report_{report_type.lower().replace(' ', '_')}.csv",
                    mime="text/csv")
                if CSV_Butten_clicked:
                    st.success("Report downloaded successfully in CSV!", icon="✅")
                    st.toast("Report downloaded successfully in CSV!", icon="✅")
            with col2:
                # Convert DataFrame to Excel
                excel_data = io.BytesIO()
                with pd.ExcelWriter(excel_data, engine='xlsxwriter') as writer:
                    df.to_excel(writer, index=False)
                    excel_data.seek(0)
                XLSX_Butten_clickeds = st.download_button(
                            label="Download Report as Excel",
                            data=excel_data,
                            file_name=f"candidate_report_{report_type.lower().replace(' ', '_')}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                if XLSX_Butten_clickeds:                
                    st.success("Data downloaded successfully in xlsx Format!",icon="✅")
                    st.toast("Data downloaded successfully in xlsx Format!", icon="✅")
            # Add summary statistics
            st.subheader("Summary Statistics")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                pending_count = len(df[df['interview_status'] == 'Pending'])
                st.metric("Pending", pending_count)
            
            with col2:
                trial_count = len(df[df['interview_status'] == 'In Trial'])
                st.metric("In Trial", trial_count)
            
            with col3:
                Selected_count = len(df[df['final_status'] == 'Selected'])
                st.metric("Selected", Selected_count)
            
            with col4:
                rejected_count = len(df[df['final_status'] == 'Rejected'])
                st.metric("Rejected", rejected_count)
            
            # Add charts
            st.subheader("Visual Analysis")
            col1, col2 ,col3,col4 ,col5 = st.columns(5)
            
            with col1:
                # Status Distribution Pie Chart
                status_counts = df['interview_status'].value_counts()
                fig1 = px.pie(
                    values=status_counts.values,
                    names=status_counts.index,
                    title='Interview Status Distribution'
                )
                st.plotly_chart(fig1)
            
            with col2:
                # Final Status Distribution Pie Chart
                final_status_counts = df['final_status'].value_counts()
                fig2 = px.pie(
                    values=final_status_counts.values,
                    names=final_status_counts.index,
                    title='Final Status Distribution'
                )
                st.plotly_chart(fig2)
            with col3:
                # Grade Distribution Pie Chart
                grade_counts = df['grade'].value_counts()
                fig3 = px.pie(
                    values=grade_counts.values,
                    names=grade_counts.index,
                    title='Grade Distribution'
                )
                st.plotly_chart(fig3)
            with col4:
                # pending statud
                pending_status_counts = df['interview_status'].value_counts()
                fig4 = px.pie(
                    values=pending_status_counts.values,
                    names=pending_status_counts.index,
                    title='Pending Status Distribution'
                )
                st.plotly_chart(fig4)
            with col5:
                #rejected 
                rejected_status_counts = df['final_status'].value_counts()
                fig5 = px.pie(
                    values=rejected_status_counts.values,
                    names=rejected_status_counts.index,
                    title='Rejected Status Distribution'
                )
                st.plotly_chart(fig5)       
        else:
            st.info("No data available for selected report type")
     # Store the previous page selection in session state
    if 'previous_page' not in st.session_state:
        st.session_state.previous_page = page
    
    elif page == "📈 :blue[**Login Analytics**]" or page == "📈 :blue[**My Login History**]":
        if st.session_state['role'] == 'admin':
            st.markdown("### :blue[**User Login Analytics Dashboard**]")
            
            # Connect to database
            conn = sqlite3.connect('candidate_evaluation.db')
            try:
                # Overall Statistics
                col1, col2, col3 = st.columns(3)
                
                # Total Active Users
                active_users = pd.read_sql_query('''
                    SELECT COUNT(DISTINCT username) as active_users
                    FROM user_sessions 
                    WHERE login_time >= date('now', '-30 days')
                ''', conn).iloc[0]['active_users']
                
                # Total Sessions Today
                sessions_today = pd.read_sql_query('''
                    SELECT COUNT(*) as sessions
                    FROM user_sessions 
                    WHERE date(login_time) = date('now')
                ''', conn).iloc[0]['sessions']
                
                # Average Session Duration
                avg_duration = pd.read_sql_query('''
                    SELECT AVG(session_duration) as avg_duration
                    FROM user_sessions 
                    WHERE session_duration IS NOT NULL
                ''', conn).iloc[0]['avg_duration']
                
                with col1:
                    st.metric("Active Users (30 days)", active_users)
                with col2:
                    st.metric("Sessions Today", sessions_today)
                with col3:
                    st.metric("Avg Session Duration (min)", 
                             round(avg_duration, 2) if avg_duration else 0)
                
                # User Activity Table
                st.markdown("### :blue[**User Activity Details**]")
                
                # Date Filter
                col1, col2 = st.columns(2)
                with col1:
                    days = st.selectbox("Time Period", 
                                      ["Last 7 days", "Last 30 days", "All time"])
                with col2:
                    sort_by = st.selectbox("Sort By", 
                                         ["Most Recent", "Most Active", "Longest Sessions"])
                
                days_map = {
                    "Last 7 days": 7,
                    "Last 30 days": 30,
                    "All time": 36500  # ~100 years
                }
                
                sort_map = {
                    "Most Recent": "MAX(login_time) DESC",
                    "Most Active": "total_sessions DESC",
                    "Longest Sessions": "avg_duration DESC"
                }
                
                query = f'''
                    SELECT 
                        username,
                        COUNT(*) as total_sessions,
                        MAX(login_time) as last_login,
                        MIN(login_time) as first_login,
                        AVG(session_duration) as avg_duration,
                        SUM(session_duration) as total_duration
                    FROM user_sessions
                    WHERE login_time >= date('now', '-{days_map[days]} days')
                    GROUP BY username
                    ORDER BY {sort_map[sort_by]}
                '''
                
                df = pd.read_sql_query(query, conn)
                
                # Format the dataframe
                if not df.empty:
                    df['last_login'] = pd.to_datetime(df['last_login']).dt.strftime('%Y-%m-%d %H:%M')
                    df['first_login'] = pd.to_datetime(df['first_login']).dt.strftime('%Y-%m-%d %H:%M')
                    df['avg_duration'] = df['avg_duration'].round(2)
                    df['total_duration'] = df['total_duration'].round(2)
                    
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No login data available for the selected period")
                
                # User Details View
                st.markdown("### :blue[**Individual User Details**]")
                selected_user = st.selectbox("Select User", df['username'].unique())
                
                if selected_user:
                    user_sessions = pd.read_sql_query('''
                        SELECT 
                            login_time,
                            logout_time,
                            session_duration
                        FROM user_sessions
                        WHERE username = ?
                        ORDER BY login_time DESC
                        LIMIT 10
                    ''', conn, params=(selected_user,))
                    
                    if not user_sessions.empty:
                        user_sessions['login_time'] = pd.to_datetime(user_sessions['login_time'])
                        user_sessions['logout_time'] = pd.to_datetime(user_sessions['logout_time'])
                        
                        st.markdown(f"**Last 10 sessions for {selected_user}**")
                        st.dataframe(user_sessions, use_container_width=True)
                    else:
                        st.info(f"No session data available for {selected_user}")
                        
            finally:
                conn.close()
                
        else:  # Regular user view
            st.markdown("### :blue[**My Login History**]")
            
            conn = sqlite3.connect('candidate_evaluation.db')
            try:
                # User's Statistics
                col1, col2, col3 = st.columns(3)
                
                stats = pd.read_sql_query('''
                    SELECT 
                        COUNT(*) as total_sessions,
                        AVG(session_duration) as avg_duration,
                        MAX(login_time) as last_login
                    FROM user_sessions
                    WHERE username = ?
                ''', conn, params=(st.session_state['username'],))
                
                with col1:
                    st.metric("Total Sessions", int(stats['total_sessions'].iloc[0]))
                with col2:
                    st.metric("Average Duration (min)", 
                             round(stats['avg_duration'].iloc[0], 2))
                with col3:
                    last_login = pd.to_datetime(stats['last_login'].iloc[0]).strftime('%Y-%m-%d %H:%M')
                    st.metric("Last Login", last_login)
                
                # Recent Sessions
                st.markdown("### :blue[**Recent Sessions**]")
                
                recent_sessions = pd.read_sql_query('''
                    SELECT 
                        login_time,
                        logout_time,
                        session_duration as duration_minutes
                    FROM user_sessions
                    WHERE username = ?
                    ORDER BY login_time DESC
                    LIMIT 10
                ''', conn, params=(st.session_state['username'],))
                
                if not recent_sessions.empty:
                    recent_sessions['login_time'] = pd.to_datetime(recent_sessions['login_time'])
                    recent_sessions['logout_time'] = pd.to_datetime(recent_sessions['logout_time'])
                    st.dataframe(recent_sessions, use_container_width=True)
                else:
                    st.info("No session history available")
                
                # Monthly Activity
                st.markdown("### :blue[**Monthly Activity**]")
                
                monthly_stats = pd.read_sql_query('''
                    SELECT 
                        strftime('%Y-%m', login_time) as month,
                        COUNT(*) as sessions,
                        AVG(session_duration) as avg_duration,
                        SUM(session_duration) as total_duration
                    FROM user_sessions
                    WHERE username = ?
                    GROUP BY strftime('%Y-%m', login_time)
                    ORDER BY month DESC
                ''', conn, params=(st.session_state['username'],))
                
                if not monthly_stats.empty:
                    monthly_stats['avg_duration'] = monthly_stats['avg_duration'].round(2)
                    monthly_stats['total_duration'] = monthly_stats['total_duration'].round(2)
                    st.dataframe(monthly_stats, use_container_width=True)
                else:
                    st.info("No monthly statistics available")
                    
            finally:
                conn.close()
    
    # Store the previous page selection in session state
    if 'previous_page' not in st.session_state:
        st.session_state.previous_page = page              
    if page == "👤 :blue[**UAssociate Details**]":
        show_associate_details()
    elif page == "💻 :blue[**UTechnical Evaluation**]":
        show_technical_evaluation()
    elif page == "📋 :blue[**UProject Evaluation**]":
        show_project_evaluation()
    elif page == "📝 :blue[**UClient Evaluation**]":
        show_client_evaluation()
    elif page == "📊 :blue[**UReports**]":
        show_reports()
if __name__ == "__main__":
    main()

    # Initialize database
    success, message = init_db()
    print(message)
    
    # Verify database
    success, message = verify_db_connection()
    print(message)
