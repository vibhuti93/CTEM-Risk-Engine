from sqlalchemy import create_engine, Column, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Define the database URL
SQLALCHEMY_DATABASE_URL = "sqlite:///./cve_data.db"

# Create the engine
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False}
)

# Create a SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a Base class for your models
Base = declarative_base()

# Define your Table model
class CVETable(Base):
    __tablename__ = "cve_records"

    cve_id = Column(String, primary_key=True, index=True)
    description = Column(String, nullable=True)
    cvss_score = Column(Float, nullable=True)
    epss_probability = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)

# Physical creation of the database tables
Base.metadata.create_all(bind=engine)