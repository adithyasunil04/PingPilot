import torch
import pandas as pd
import numpy as np
from sys import argv
from os.path import isfile, join
from os import listdir

def list_pt_files():
    """
    List all .pt files in the datasets directory
    """
    try:
        files = [f for f in listdir('datasets') if f.endswith('.pt')]
        if not files:
            print("\nNo .pt files found in datasets/ directory!")
            return
        
        print("\nAvailable .pt files in datasets/ directory:")
        for i, file in enumerate(files, 1):
            print(f"{i}. {file}")
        return files
    except FileNotFoundError:
        print("\nError: datasets/ directory not found!")
        return None

def pt_to_csv(pt_filename):
    """
    Convert PyTorch .pt dataset file to CSV format
    Args:
        pt_filename (str): Name of the .pt file to convert
    Returns:
        None (saves CSV file)
    """
    try:
        # Load the .pt file
        print(f"\nLoading {pt_filename}...")
        X, y = torch.load(pt_filename)
        
        # Get timestamp and capture duration from filename
        file_parts = pt_filename.split('_')
        timestamp_date = file_parts[-3]
        timestamp_time = file_parts[-2]
        
        # Convert X tensor to numpy array and create DataFrame
        X_np = X.numpy()
        
        # Create column names for features
        feature_columns = [f'feature_{i+1}' for i in range(X_np.shape[1])]
        
        # Create DataFrame with features
        df = pd.DataFrame(X_np, columns=feature_columns)
        
        # Add labels column
        df['label'] = y
        
        # Add metadata columns
        df['timestamp_date'] = timestamp_date
        df['timestamp_time'] = timestamp_time
        df['capture_duration'] = capture_duration
        
        # Generate output filename
        csv_filename = pt_filename.replace('.pt', '.csv')
        
        # Save to CSV
        print(f"Saving to {csv_filename}...")
        df.to_csv(csv_filename, index=False)
        print("Conversion completed successfully!")
        
        # Print dataset statistics
        print("\nDataset Statistics:")
        print(f"Number of samples: {len(df)}")
        print(f"Number of features: {len(feature_columns)}")
        print(f"Label distribution:\n{df['label'].value_counts()}")
        print(f"\nCapture Duration: {capture_duration} seconds")
        print(f"Timestamp Date: {timestamp_date}")
        print(f"Timestamp Time: {timestamp_time}")
        
    except Exception as e:
        print(f"Error during conversion: {str(e)}")

def main():
    # If argument is provided, use it directly
    if len(argv) > 1:
        pt_filename = argv[1]
        if not isfile(pt_filename):
            print("Error: File does not exist!")
            return
        if not pt_filename.endswith('.pt'):
            print("Error: File must be a .pt file!")
            return
    
    # If no argument, list files in datasets/ and ask user to choose
    else:
        files = list_pt_files()
        if not files:
            return
            
        while True:
            choice = input("\nEnter the number of the file to convert (or 'q' to quit): ")
            if choice.lower() == 'q':
                return
                
            try:
                file_index = int(choice) - 1
                if 0 <= file_index < len(files):
                    pt_filename = join('datasets', files[file_index])
                    break
                else:
                    print("Invalid file number! Please try again.")
            except ValueError:
                print("Please enter a valid number or 'q' to quit.")
    
    pt_to_csv(pt_filename)

if __name__ == "__main__":
    main()