import os
import keyring
import argparse
import logging
import datetime
import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
import sys

__author__ = 'Jesse'

logging.basicConfig(format="[%(asctime)s] [%(levelname)8s] --- %(message)s (%(filename)s:%(lineno)s)",
                    level=logging.DEBUG)

BASE = declarative_base()  # Needs to be module level w/ database


class DatabaseHelper:
    # from sqlalchemy.dialects.sqlite import \
    # BLOB, BOOLEAN, CHAR, DATE, DATETIME, DECIMAL, FLOAT, \
    # INTEGER, NUMERIC, SMALLINT, TEXT, TIME, TIMESTAMP, \
    # VARCHAR

    def create_tables(self):
        logging.debug('Creating table if not already present')
        engine = self.get_engine()
        print('Are you sure to want to DROP ALL TABLES, this cannot be undone!')
        if input('({0})>'.format('Type YES to continue')) == 'YES':
            logging.info("Resetting master key")
            keyring.set_password("AutoBackup", "DBkey", Fernet.generate_key())
            BASE.metadata.drop_all(engine)
            BASE.metadata.create_all(engine)
            print('DATABASE RE-INITIALIZED')
        else:
            print('Skipping database re-initialization')

    @staticmethod
    def get_engine():
        return sqlalchemy.create_engine('sqlite:///AutoBackupData.db')

    @staticmethod
    def get_session():
        engine = DatabaseHelper.get_engine()
        BASE.metadata.bind = engine
        DBSession = sqlalchemy.orm.sessionmaker(bind=engine)
        return DBSession()

    def get_all_rows(self):
        session = self.get_session()
        return session.query(EnvData).all()

    def get_last_x_rows(self, x):
        session = self.get_session()
        return session.query(EnvData).order_by(EnvData.row_id.desc()).limit(x).all()

    def add_data(self, data_obj, client_ip):

        # Create DB obj class instance
        db_entry = EnvData()
        db_entry.client_ip = client_ip
        db_entry.timestamp = datetime.datetime.now().isoformat()
        db_entry.altitude = data_obj['altitude']
        db_entry.p = data_obj['p']
        db_entry.temp = data_obj['temp']

        # Write DB obj to disk
        s = self.get_session()
        s.add(db_entry)
        s.commit()

    @staticmethod
    def get_password(hash_pass_in):
        f = Fernet(keyring.get_password("AutoBackup", "DBkey"))
        return f.decrypt(hash_pass_in)

    @staticmethod
    def set_password(password_in):
        f = Fernet(keyring.get_password("AutoBackup", "DBkey"))
        return f.encrypt(password_in)

# Classes are directly mapped to tables, without the need for a mapper binding (ex mapper(Class, table_definition))
class EnvData(BASE):
    from sqlalchemy import Column, Integer, String
    """Defines Device object relational model, is used for both table creation and object interaction"""
    __tablename__ = 'EnvData'
    row_id = Column('row_id', Integer, primary_key=True)
    timestamp = Column('timestamp', String)
    client_ip = Column('client_ip', String, nullable=False)
    temp = Column('temp', String, nullable=False)
    p = Column('p', String, nullable=False)
    altitude = Column('altitude', String, nullable=False)


class main(object):
    @staticmethod
    def run():
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--setup", action="store_true", help="Setup Environment")
        args = parser.parse_args()

        if args.setup:
            DatabaseHelper().create_tables()
            sys.exit(0)


        # Put this somewhere safe!




if __name__ == "__main__":
    main.run()
