import pandas as pd
import os

# 1. Dataset Configuration
file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'phishing_site_urls.csv')

try:
    # Loading the dataset into a Pandas DataFrame
    df = pd.read_csv(file_path)
    
    print("✅ System: Pandas library initialized and dataset loaded successfully.")
    print("-" * 60)
    
    # 2. Data Dimensions (Rows and Columns)
    print(f"📊 Dataset Dimensions: {df.shape[0]} URL entries with {df.shape[1]} features.")
    
    # 3. Features Overview (Column names for technical review)
    print(f"📝 Available Columns: {list(df.columns)}")
    
    # 4. Data Preview (Displaying the first 5 records)
    print("\n🧐 Sample Data Preview:")
    print(df.head())
    
    # 5. Class Distribution Analysis (Benign vs. Malicious)
    print("\n⚖️ Label Distribution (Target Analysis):")
    print(df['Label'].value_counts())

except FileNotFoundError:
    print("❌ Error: Dataset file not found. Please ensure 'phishing_site_urls.csv' is in the data folder.")
except Exception as e:
    print(f"❌ Unexpected Error: {e}")