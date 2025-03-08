''' IMPORT TEMPLATE
import module                   # where its used
'''

import click                    # cli
from fastapi import FastAPI     # rest api
import uvicorn                  # rest api
from pydantic import BaseModel  # rest api
import os                       # rest api

from datetime import datetime   # logs
import threading                # logs

import sqlite3                  # database
from sqlite3 import Error       # database

    
###
### Constants
###
LOG_FILE        = "collector.log"
DB_FILE         = "events.db"
DB_TABLE_NAME   = "Events"


class Event(BaseModel):
    rule_name: str
    source_file: str 
    description: str

###
### REST API
###
        
app = FastAPI()

@app.post(f"/upload")
def upload_file(event: Event):
    
    def cli_print():
        print("\n====Received a new event=====\n")
        print(event)
        print()
    
    def log_print(message: str):
        log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] # trimming to miliseconds
        thread_id = threading.current_thread().ident
        message = f'[{log_time}] INFO [{thread_id}] - {message} a new event detected by "{event.rule_name}" rule in "{event.source_file}".\n'
        
        with open(LOG_FILE, 'a') as log_file:
            log_file.write(message)
    
    def sql_print():
        con = get_database(DB_FILE)
        event_parameters = event_to_parameters(event)
        insert_event(con, event_parameters)
        
        log_print("Saved")
    
    log_print("Received")
    cli_print()
    sql_print()
    
###
### SQLite
###

def get_database(db_file):
    con = None
    try:
        con = sqlite3.connect(db_file)
    except Error as e:
        print(e)
        
    query = f"CREATE TABLE IF NOT EXISTS {DB_TABLE_NAME}(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, rule_name CHAR, source_file CHAR, description CHAR)" 
    
    cur = con.cursor()
    cur.execute(query)
    con.commit()
    
    return con

def insert_event(con, event_parameters):
    sql = f"INSERT INTO {DB_TABLE_NAME}(timestamp, rule_name, source_file, description) VALUES(CAST( strftime('%s', 'now') AS INT ),?,?,?)" 
    
    cur = con.cursor()
    cur.execute(sql, event_parameters)
    con.commit()
    
def event_to_parameters(event: Event) -> list:
    return [event.rule_name, event.source_file, event.description] 

def select_events(filter=None, search_string=None, start_date=None, end_date=None):
    con = get_database(DB_FILE)
    cur = con.cursor()

    if filter is None:
        query = f"SELECT * FROM {DB_TABLE_NAME} ORDER BY id"
        results = cur.execute(query)
    elif filter == 'rule_name':
        query = f"SELECT * FROM {DB_TABLE_NAME} WHERE rule_name LIKE ? ORDER BY id"
        results = cur.execute(query, (search_string, ))  
    elif filter == 'source_file':
        query = f"SELECT * FROM {DB_TABLE_NAME} WHERE source_file LIKE ? ORDER BY id"
        results = cur.execute(query, (search_string, ))  
    elif filter == 'date':
        if start_date is None: # earlier than
            query = f"SELECT * FROM {DB_TABLE_NAME} WHERE timestamp <= ? ORDER BY id"
            results = cur.execute(query, (end_date, ))  
        elif end_date is None: # later than
            query = f"SELECT * FROM {DB_TABLE_NAME} WHERE timestamp >= ? ORDER BY id"
            results = cur.execute(query, (start_date, ))
        else:                  # between
            query = f"SELECT * FROM {DB_TABLE_NAME} WHERE timestamp BETWEEN ? AND ? ORDER BY id"
            results = cur.execute(query, (start_date, end_date, ))
    
    return results

###
### Click
###
@click.group()
def cli():
    pass

@cli.command()
@click.option('--host', default="localhost", help="Hostname of API server (Default: localhost)")
@click.option('--port', default=8000, help="Port of API server (Default: 8000)")
def filedump(host, port):
    """REST API server start and continous CLI view"""

    create_logfile()
    
    file_name = os.path.basename(__file__)[:-3] # trimming the .py extension
    uvicorn.run(f"{file_name}:app", host=host, port=port, log_config='log.ini')
  
@cli.command()
@click.option('-f','--filter', type=click.Choice(['rule_name','source_file', 'date']), help="Select the type of filter to use")
@click.option('-s','--start_date', type=int, help="Unix timestamp of earliest date")
@click.option('-e','--end_date', type=int, help="Unix timestamp of latest date")
@click.argument('filter_string', required=False)
def sqlview(filter, start_date, end_date, filter_string=None):
    """View event history with filtering options"""

    if filter is None:
        for row in select_events():
            print(row)
    elif filter == 'date': # if date is selected
        if start_date is None and end_date is None: # check if any of the required parameters was provided
            print("Argument start_date or end_date is required if filter is selected")
        else:
            for row in select_events(filter=filter, start_date=start_date, end_date=end_date):
                print(row)
    elif filter_string is not None: # check if filter was given and search string passed
        for row in select_events(filter=filter, search_string=filter_string):
            print(row)
    else: # if filter was selected and no search string was given
        print("Argument filter_string is required if filter is selected")
        
###
### Startup
###

def create_logfile():
    if os.path.exists(LOG_FILE):
        return
    
    with open(LOG_FILE, 'w') as _:
        pass    
        
if __name__ == '__main__':
    cli()