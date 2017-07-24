import base64
import subprocess
import keyring
import argparse
import logging
import sqlalchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
from prettytable import PrettyTable
import sys
import unittest
import getpass
import platform

__author__ = 'Jesse'

logging.basicConfig(format="[%(asctime)s] [%(levelname)8s] --- %(message)s (%(filename)s:%(lineno)s)",
                    level=logging.DEBUG)

BASE = declarative_base()  # Needs to be module level w/ database


class PasswordHelper:
    application_name = 'AutoBackup'
    master_hash_key_location = 'key'  # Can be overridden for testing

    def setup_master_key(self):
        logging.debug("Setting up master key")
        key = Fernet.generate_key()
        encode_key = base64.urlsafe_b64encode(key).decode("utf-8")  # Convert to string for storage
        logging.debug(encode_key)
        keyring.set_password(self.application_name, self.master_hash_key_location, encode_key)

    def get_master_pass(self):
        key_pass = keyring.get_password(self.application_name, self.master_hash_key_location)
        decode_key_pass = base64.urlsafe_b64decode(key_pass)
        return decode_key_pass

    def decode_password(self, hash_pass_in):
        f = Fernet(self.get_master_pass())
        return f.decrypt(hash_pass_in).decode("utf-8")

    def encode_password(self, password_in):
        f = Fernet(self.get_master_pass())
        return f.encrypt(password_in.encode("utf-8"))


class SshHelper:
    server = ""
    username = ""
    password = ""
    port = 22
    command = ""
    output = None

    def send_command(self):
        if platform.system() == 'Windows':
            # TODO Write separate methods for each OS
            pre = "cmd.exe /c echo y |"  # ACCEPT KEY
            exe = '\"C:\Program Files\PuTTY\plink.exe\" '  # There should be a space here
            s0 = pre + exe + '-P {2} -ssh {0}@{1} "exit"'.format(self.username, self.server, self.port)
            logging.debug(s0)
            subprocess.call(s0, timeout=2)  # Wait x seconds for key to get saved

            s1 = exe + '-pw {3} -P {2} -ssh {0}@{1} "{4}"'.format(self.username, self.server, self.port, self.password,
                                                                  self.command)
            logging.debug(s1)
            o = subprocess.check_output(s1, shell=True)
            return o
        if platform.system() == 'Linux':
            pass
            # TODO Write linux SSH CLI code


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
        s = self.get_session()
        return s.query(Database_ORM).all()

    def add_data(self):
        db_entry = Database_ORM()  # Create DB obj class instance
        db_entry.ssh_ip = input('Enter ssh_ip:')
        db_entry.ssh_port = input('Enter ssh_port:')
        db_entry.ssh_username = input('Enter ssh_username:')
        db_entry.ssh_password = PasswordHelper().encode_password(getpass.getpass('Enter ssh_password:'))
        db_entry.ssh_command = input('Enter ssh_command:')
        s = self.get_session()
        s.add(db_entry)
        s.commit()

    def modify_row(self):
        try:
            row_to_edit = int(input('Enter row to edit:'))
            s = self.get_session()
            o = s.query(Database_ORM).filter_by(row_id=row_to_edit).first()
            ip = input('Enter ssh_ip [' + o.ssh_ip + ']:')
            if ip != '':
                o.ssh_ip = ip

            port = input('Enter ssh_port [' + str(o.ssh_port) + ']:')
            if port != '':
                o.ssh_port = int(port)

            user = input('Enter ssh_username [' + o.ssh_username + ']:')
            if user != '':
                o.ssh_username = user

            # FIXME Even if user does not change password, it gets invalidated
            password = PasswordHelper().encode_password(getpass.getpass('Enter ssh_password:'))
            if password != '':
                o.ssh_password = password

            command = input('Enter ssh_command [' + o.ssh_command + ']:')
            if command != '':
                o.ssh_command = command
            s.commit()
        except ValueError:
            print("No row removed")

    def delete_row(self):
        row_to_remove = None
        try:
            row_to_remove = int(input('Enter row to remove:'))
        except ValueError:
            print("No row removed")
        s = self.get_session()
        s.query(Database_ORM).filter_by(row_id=row_to_remove).delete()
        s.commit()


class TableOutput:
    @staticmethod
    def generate_table_data():
        rows = DatabaseHelper().get_all_rows()
        data_rows = []
        header_row = ['row_id', 'ssh_ip', 'ssh_port', 'ssh_username', 'ssh_command']
        for i in rows:
            data_rows.append([i.row_id, i.ssh_ip, i.ssh_port, i.ssh_username, i.ssh_command])
        return TableOutput.create_table(header_list_in=header_row, data_list_in=data_rows)

    @staticmethod
    def create_table(header_list_in=None, data_list_in=None):
        t = PrettyTable(header_list_in)
        for i in data_list_in:
            t.add_row(i)
        return str(t)


# Classes are directly mapped to tables, without the need for a mapper binding (ex mapper(Class, table_definition))
class Database_ORM(BASE):
    from sqlalchemy import Column, Integer, String
    """Defines Device object relational model, is used for both table creation and object interaction"""
    __tablename__ = 'Database_ORM'
    row_id = Column('row_id', Integer, primary_key=True)
    ssh_ip = Column('ssh_ip', String, nullable=False)
    ssh_port = Column('ssh_port', Integer, nullable=False)
    ssh_username = Column('ssh_username', String, nullable=False)
    ssh_password = Column('ssh_password', String, nullable=False)
    ssh_command = Column('ssh_command', String, nullable=False)


class main:
    @staticmethod
    def run_commands():
        rows = DatabaseHelper().get_all_rows()
        for i in rows:
            h = SshHelper()
            h.server = i.ssh_ip
            h.port = i.ssh_port
            h.username = i.ssh_username
            h.password = PasswordHelper().decode_password(i.ssh_password)
            h.command = i.ssh_command
            o = h.send_command()
            logging.debug(o)

    @staticmethod
    def run():
        parser = argparse.ArgumentParser()
        parser.add_argument("-s", "--setup", action="store_true", help="Setup Environment")
        parser.add_argument("-g", "--get_rows", action="store_true", help="Print Rows")
        parser.add_argument("-a", "--add_row", action="store_true", help="Add Entry to Database")
        parser.add_argument("-m", "--modify_row", action="store_true", help="Modify Entry in Database")
        parser.add_argument("-r", "--remove_row", action="store_true", help="Remove Row")
        parser.add_argument("-e", "--exec_commands", action="store_true", help="Execute Commands")
        args = parser.parse_args()

        if args.setup:
            PasswordHelper().setup_master_key()
            DatabaseHelper().create_tables()
            sys.exit(0)

        if args.add_row:
            print(TableOutput.generate_table_data())
            DatabaseHelper().add_data()
            sys.exit(0)

        if args.modify_row:
            print(TableOutput.generate_table_data())
            DatabaseHelper().modify_row()
            sys.exit(0)

        if args.get_rows:
            print(TableOutput.generate_table_data())
            sys.exit(0)

        if args.remove_row:
            print(TableOutput.generate_table_data())
            DatabaseHelper().delete_row()
            sys.exit(0)

        if args.exec_commands:
            main.run_commands()
            sys.exit(0)


if __name__ == "__main__":
    main.run()


class UnitTests(unittest.TestCase):
    def test_password_encoding(self):
        ph = PasswordHelper()
        ph.master_hash_key_location = "unit_test"
        ph.setup_master_key()
        password = "AwesomeTestPassword"  # Test Password
        logging.debug("Input password")
        logging.debug(password)
        password_in_database = ph.encode_password(password)  # Encodes to bytes
        logging.debug("Encoded password")
        logging.debug(password_in_database)
        logging.debug("Decoded password")
        decoded_pass = ph.decode_password(password_in_database)
        logging.debug(decoded_pass)
        self.assertEqual(password, decoded_pass)
