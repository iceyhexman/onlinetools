from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
engine=create_engine("sqlite:///./../scan.db")
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    import scanner.model.user
    import scanner.model.scanover
    import scanner.model.process

    Base.metadata.create_all(bind=engine)


if __name__ == '__main__':
    try:
        init_db()
        print("[+]database built success!")
    except:
        print("[-] error! database built failed")
