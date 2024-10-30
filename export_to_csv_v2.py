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

def inspect_dataset(pt_filename):
    """
    Inspect and print details about the PyTorch dataset
    """
    print(f"\nInspecting {pt_filename}...")
    
    try:
        # Load with weights_only=False explicitly
        data = torch.load(pt_filename, weights_only=False)
        
        print("\nDataset Structure:")
        if isinstance(data, tuple):
            print(f"Dataset is a tuple with {len(data)} elements")
            for i, item in enumerate(data):
                print(f"\nElement {i}:")
                print(f"Type: {type(item)}")
                if isinstance(item, torch.Tensor):
                    print(f"Shape: {item.shape}")
                    print(f"Dtype: {item.dtype}")
                    print(f"Device: {item.device}")
                    print("\nFirst few values:")
                    print(item[:2])  # Show first 2 items
        else:
            print(f"Dataset is a single item of type: {type(data)}")
            if isinstance(data, torch.Tensor):
                print(f"Shape: {data.shape}")
                print(f"Dtype: {data.dtype}")
                print(f"Device: {data.device}")
        
        return data
        
    except Exception as e:
        print(f"Error during inspection: {str(e)}")
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
        # First inspect the dataset
        data = inspect_dataset(pt_filename)
        if data is None:
            return
        
        # Unpack the data
        if isinstance(data, tuple) and len(data) >= 2:
            X, y = data[:2]
        else:
            print("Error: Dataset structure not as expected!")
            return
            
        # Get timestamp and capture duration from filename
        file_parts = pt_filename.split('_')
        timestamp_date = file_parts[-3]
        timestamp_time = file_parts[-2]
        capture_duration = file_parts[-1].split('.')[0]
        
        # Handle 3D tensor (samples, timesteps, features)
        if len(X.shape) == 3:
            samples, timesteps, features = X.shape
            print(f"\nFound 3D tensor with shape: {X.shape}")
            print(f"Samples: {samples}, Timesteps: {timesteps}, Features: {features}")
            
            # Option 1: Flatten timesteps and features
            X_reshaped = X.reshape(samples, timesteps * features)
            print(f"Reshaped to 2D: {X_reshaped.shape}")
            
            # Convert to numpy array
            X_np = X_reshaped.numpy()
            
            # Create column names for flattened features
            feature_columns = [f'timestep_{t}_feature_{f}' 
                             for t in range(timesteps) 
                             for f in range(features)]
            
        else:
            X_np = X.numpy()
            feature_columns = [f'feature_{i+1}' for i in range(X_np.shape[1])]
        
        # Create DataFrame
        df = pd.DataFrame(X_np, columns=feature_columns)
        
        # Handle labels - convert list to numpy array if necessary
        if isinstance(y, list):
            y_np = np.array(y)
        else:
            y_np = y.numpy()
        
        # Add labels column
        df['label'] = y_np
        
        # Add metadata columns
        df['timestamp_date'] = timestamp_date
        df['timestamp_time'] = timestamp_time
        df['capture_duration'] = capture_duration
        
        # Generate output filename
        csv_filename = pt_filename.replace('.pt', '.csv')
        
        # Save to CSV
        print(f"\nSaving to {csv_filename}...")
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
        import traceback
        print("\nFull traceback:")
        print(traceback.format_exc())

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