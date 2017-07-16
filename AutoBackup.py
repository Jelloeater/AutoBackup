import base64
import keyring
import argparse
import logging
import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
import sys

__author__ = 'Jesse'

logging.basicConfig(format="[%(asctime)s] [%(levelname)8s] --- %(message)s (%(filename)s:%(lineno)s)",
                    level=logging.DEBUG)

BASE = declarative_base()  # Needs to be module level w/ database


class PasswordHelper:
    @staticmethod
    def setup_master_key():
        logging.debug("Setting up master key")
        key = Fernet.generate_key()
        logging.debug(key)
        encode_key = base64.urlsafe_b64encode(key)
        logging.debug(encode_key)
        keyring.set_password("AutoBackup", "DBkey", encode_key)

    @staticmethod
    def get_master_pass():
        key_pass = keyring.get_password("AutoBackup", "DBkey")
        decode_key_pass = base64.urlsafe_b64decode(key_pass)
        return decode_key_pass

    @staticmethod
    def decode_password(hash_pass_in):
        f = Fernet(PasswordHelper.get_master_pass())
        return f.decrypt(hash_pass_in)

    @staticmethod
    def encode_password(password_in):
        f = Fernet(PasswordHelper.get_master_pass())
        return f.encrypt(password_in)


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
        return session.query(Database_ORM).all()

    def add_data(self):
        db_entry = Database_ORM()  # Create DB obj class instance
        db_entry.ssh_ip = input('Enter ssh_ip:')
        db_entry.ssh_username = input('Enter ssh_username:')
        db_entry.ssh_password = PasswordHelper.encode_password(input('Enter ssh_password:'))
        db_entry.ssh_command = input('Enter ssh_command:')
        s = self.get_session()
        s.add(db_entry)
        s.commit()  # Write DB obj to disk


# Classes are directly mapped to tables, without the need for a mapper binding (ex mapper(Class, table_definition))
class Database_ORM(BASE):
    from sqlalchemy import Column, Integer, String
    """Defines Device object relational model, is used for both table creation and object interaction"""
    __tablename__ = 'Database_ORM'
    row_id = Column('row_id', Integer, primary_key=True)
    ssh_ip = Column('ssh_ip', String, nullable=False)
    ssh_username = Column('ssh_username', String, nullable=False)
    ssh_password = Column('ssh_password', String, nullable=False)
    ssh_command = Column('ssh_command', String, nullable=False)


class main(object):
    @staticmethod
    def run():
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--setup", action="store_true", help="Setup Environment")
        parser.add_argument("-a", "--add", action="store_true", help="Add Entry to Database")
        args = parser.parse_args()

        if args.setup:
            PasswordHelper.setup_master_key()
            DatabaseHelper().create_tables()
            sys.exit(0)

        if args.add:
            DatabaseHelper().add_data()
            sys.exit(0)

        PasswordHelper.setup_master_key()
        encoded = PasswordHelper.encode_password(input('Enter ssh_password:'))
        print("Your pass = " + PasswordHelper.decode_password(encoded))


if __name__ == "__main__":
    main.run()
