# ------------------------------------© SHANSKAR BANSAL ©------------------------------------# 
# -----------------------------        streamlit-aggrid       -------------------------------#

import streamlit as st
from google.cloud import bigquery
from google.oauth2 import service_account
import pandas as pd
import hashlib
import re
import requests
from st_aggrid import AgGrid, GridOptionsBuilder, JsCode, GridUpdateMode

key_path = st.secrets["bigquery_service_account"]
credentials = service_account.Credentials.from_service_account_info(
    key_path, scopes=["https://www.googleapis.com/auth/cloud-platform"]
)

client = bigquery.Client(credentials=credentials, project=credentials.project_id)

HUNTER_API_KEY = "f1c95af76fd9526e60ec1cc90b36199c558a7f54"

table_configurations = {
    'comms-engineering.FACEBOOK_DATASET.FB_PAGE_TABLE': {'date_column': 'Date', 'date_format': '%d-%m-%Y'},
    'comms-engineering.FACEBOOK_DATASET.FB_POST_TABLE': {'date_column': 'Publish_Time', 'date_format': '%Y-%m-%d'},
    'comms-engineering.FACEBOOK_DATASET.FB_POST_WEEK_TABLE': {'date_column': 'Publish_Time', 'date_format': '%Y-%m-%d'}
    'comms-engineering.FACEBOOK_DATASET.FB_PAGE_WEEK_TABLE': {'date_column': 'Date', 'date_format': '%d-%m-%Y'},
    
}

def load_data(table_id, start_date, end_date):
    config = table_configurations[table_id]
    formatted_start_date = pd.to_datetime(start_date).strftime(config['date_format'])
    formatted_end_date = pd.to_datetime(end_date).strftime(config['date_format'])
    
    query = f"""
    SELECT * FROM `{table_id}`
    WHERE {config['date_column']} BETWEEN '{formatted_start_date}' AND '{formatted_end_date}'
    """
    return client.query(query).to_dataframe()

def update_data(updated_df, table_id):
    config = table_configurations[table_id]
    if config['date_column'] in updated_df.columns:
        updated_df[config['date_column']] = pd.to_datetime(updated_df[config['date_column']]).dt.strftime(config['date_format'])        
    updated_df.reset_index(drop=True, inplace=True)
    job = client.load_table_from_dataframe(updated_df, table_id, job_config=bigquery.LoadJobConfig(write_disposition="WRITE_TRUNCATE"))
    job.result()

def insert_data(new_row, table_id):
    for key in new_row.keys():
        if new_row[key] == '':
            new_row[key] = 0 if pd.api.types.is_integer_dtype(st.session_state['df'][key]) else None
    
    errors = client.insert_rows_json(table_id, [new_row])
    if errors:
        st.error(f"Failed to insert row: {errors}")
    else:
        st.success("New row inserted successfully!")

def delete_data(delete_condition, table_id):
    st.warning("😆 Kyu karna hai bhai delete 😆")

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def check_user(email, password):
    query = f"""
    SELECT * FROM `comms-engineering.login.password`
    WHERE email = '{email}' AND password = '{hash_password(password)}' AND status = 'active'
    """
    df = client.query(query).to_dataframe()
    return not df.empty

def check_user_exists(email):
    query = f"""
    SELECT * FROM `comms-engineering.login.password`
    WHERE email = '{email}' AND status = 'active'
    """
    df = client.query(query).to_dataframe()
    return not df.empty

def update_password(email, new_password):
    hashed_password = hash_password(new_password)
    
    new_user = {'email': email, 'password': hashed_password, 'status': 'active'}
    errors = client.insert_rows_json('comms-engineering.login.password', [new_user])
    if errors:
        st.error(f"Failed to update password: {errors}")
    else:
        st.success("Password updated successfully.")

def validate_email_format(email):
    regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.match(regex, email)

def validate_email_exists(email):
    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}"
    response = requests.get(url)
    data = response.json()
    return data.get('data', {}).get('result') == 'deliverable' 

def is_varaheanalytics_email(email):
    return email.split('@')[1] == 'varaheanalytics.com'

def register_user(email, password):
    if not validate_email_format(email):
        st.error("Invalid email format")
        return
    
    if not is_varaheanalytics_email(email):
        st.error("Registration is restricted to Varahe Analytics email addresses")
        return
    
    if check_user_exists(email):
        st.error("User already exists")
        return
    
    if not validate_email_exists(email):
        st.error("Email does not exist")
        return
    
    new_user = {'email': email, 'password': hash_password(password), 'status': 'active'}
    errors = client.insert_rows_json('comms-engineering.login.password', [new_user])
    if errors:
        st.error(f"Failed to register user: {errors}")
    else:
        st.success("User registered successfully!")

def login():
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if not is_varaheanalytics_email(email):
            st.error("Login is restricted to Varahe Analytics email addresses")
        elif check_user(email, password):
            st.session_state['logged_in'] = True
            st.session_state['email'] = email
        else:
            st.error("Invalid email or password")

def register():
    st.subheader("Register")
    new_email = st.text_input("New Email")
    new_password = st.text_input("New Password", type="password")
    if st.button("Register"):
        register_user(new_email, new_password)

def forgot_password():
    st.subheader("Forgot Password")
    email = st.text_input("Email")
    if st.button("Verify Email"):
        if is_varaheanalytics_email(email) and check_user_exists(email):
            st.session_state['reset_email'] = email
            st.session_state['reset_verified'] = True
            st.success("Email verified. Please enter a new password.")
        else:
            st.error("Email does not exist or is not a Varahe Analytics email.")
    
    if st.session_state.get('reset_verified', False):
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        if st.button("Reset Password"):
            if new_password == confirm_password:
                update_password(st.session_state['reset_email'], new_password)
                st.success("Password has been reset successfully.")
                st.session_state['reset_verified'] = False
                st.session_state['reset_email'] = None
            else:
                st.error("Passwords do not match.")

st.set_page_config(page_title='BigQuery Data Editor', page_icon=':pencil:', layout='wide')

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

if st.session_state['logged_in']:
    st.image('https://media.licdn.com/dms/image/C4D0BAQHxlx31iRVpcQ/company-logo_200_200/0/1654155578017?e=1726099200&v=beta&t=41pCBzTxlFnZG43IlklTbQpRnirE8szdB27p8zN2HFg', width=200) 
    st.title('BigQuery Data Editor')

    table_id = st.sidebar.selectbox('Select Table', tuple(table_configurations.keys()))
    start_date = st.sidebar.date_input("Start Date")
    end_date = st.sidebar.date_input("End Date")
    operation = st.sidebar.radio("Select Operation", ('Load Data', 'Insert New Row', 'Delete Rows', 'Save Changes to BigQuery'))

    if operation == 'Load Data':
        st.subheader('Load and Edit Data')
        if st.sidebar.button('Load Data'):
            df = load_data(table_id, start_date, end_date)
            if 'Content_Produced_By' not in df.columns:
                df['Content_Produced_By'] = 'Select' 
            df['Content_Produced_By'] = pd.Categorical(df['Content_Produced_By'], categories=['varahe', 'party'])

            if 'Content_Category' not in df.columns:
                df['Content_Category'] = 'Select'
            df['Content_Category'] = pd.Categorical(df['Content_Category'], categories=['Anti-Modi', 'Pro-Modi'])

            if 'Content_Nature' not in df.columns:
                df['Content_Nature'] = 'Select'
            df['Content_Nature'] = pd.Categorical(df['Content_Nature'], categories=['Positive', 'Negative'])

            st.session_state['df'] = df

        if 'df' in st.session_state:
            gb = GridOptionsBuilder.from_dataframe(st.session_state['df'])

            gb.configure_column("Content_Produced_By", editable=True, cellEditor='agSelectCellEditor',
                                cellEditorParams={'values': ['varahe', 'party']})
            gb.configure_column("Content_Category", editable=True, cellEditor='agSelectCellEditor',
                                cellEditorParams={'values': ['Anti-Modi', 'Pro-Modi']})
            gb.configure_column("Content_Nature", editable=True, cellEditor='agSelectCellEditor',
                                cellEditorParams={'values': ['Positive', 'Negative']})

            grid_options = gb.build()

            grid_response = AgGrid(
                st.session_state['df'],
                gridOptions=grid_options,
                enable_enterprise_modules=True,
                allow_unsafe_jscode=True,  
                update_mode=GridUpdateMode.VALUE_CHANGED,  
                fit_columns_on_grid_load=False,
                height=300,  
                width='100%'
            )

            st.session_state['df'] = grid_response['data']
            st.markdown("### Updated Data")
            st.dataframe(st.session_state['df']) 

    elif operation == 'Insert New Row':
        st.subheader('Insert New Row')
        if 'df' in st.session_state:
            new_row = {col: st.text_input(f'Enter value for {col}:', key=f'insert_{col}') for col in st.session_state['df'].columns}
            if st.button('Insert New Row'):
                insert_data(new_row, table_id)
                st.session_state['df'] = load_data(table_id, start_date, end_date) 

    elif operation == 'Delete Rows':
        st.subheader('Delete Rows')
        delete_condition = st.text_input('Enter condition to delete rows (e.g., "id = 1")', key='delete_condition')
        if st.button('Delete Row'):
            delete_data(delete_condition, table_id)
            st.session_state['df'] = load_data(table_id, start_date, end_date)  

    elif operation == 'Save Changes to BigQuery':
        st.subheader('Save Changes to BigQuery')
        if 'df' in st.session_state:
            edited_df = st.data_editor(st.session_state['df'], key='data_editor')
            if st.button('Save Changes to BigQuery'):
                update_data(edited_df, table_id)
                st.success('Data updated in BigQuery!')
                st.session_state['df'] = load_data(table_id, start_date, end_date) 

    st.sidebar.markdown("---")
    st.sidebar.markdown("© Varahe Analytics Private Limited")
else:
    st.sidebar.image('https://media.licdn.com/dms/image/C4D0BAQHxlx31iRVpcQ/company-logo_200_200/0/1654155578017?e=1726099200&v=beta&t=41pCBzTxlFnZG43IlklTbQpRnirE8szdB27p8zN2HFg', width=200)
    choice = st.sidebar.selectbox("Select Action", ["Login", "Register", "Forgot Password"])
    if choice == "Login":
        login()
    elif choice == "Register":
        register()
    elif choice == "Forgot Password":
        forgot_password()

    st.sidebar.markdown("---")
    st.sidebar.markdown("© Varahe Analytics Private Limited")
