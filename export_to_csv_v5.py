import torch
import pandas as pd
import os
import sys
import re


# to open dataset with 12 features

def pt_to_csv(pt_file_path=None):
    try:
        # Check if pt_file_path is provided
        if not pt_file_path:
            # Look for .pt files in datasets/ directory
            datasets_dir = os.path.join(os.getcwd(), 'datasets')
            pt_files = [f for f in os.listdir(datasets_dir) if f.endswith('.pt')]
            
            # If no .pt files are found, return an error code
            if not pt_files:
                print("No .pt files found in datasets/ directory.")
                return 1
            
            # Prompt the user to select a file if multiple .pt files are present
            print("Available .pt files in datasets/:")
            for i, f in enumerate(pt_files, 1):
                print(f"{i}: {f}")
            choice = int(input("Select a file number to convert to CSV: ")) - 1
            
            # Set the selected file path
            pt_file_path = os.path.join(datasets_dir, pt_files[choice])
        else:
            # Use provided file path if it exists
            if not os.path.exists(pt_file_path):
                print(f"File '{pt_file_path}' not found.")
                return 1

        # Load the .pt file
        X_tensor, labels, *_ = torch.load(pt_file_path)

        # Convert tensor to numpy array and flatten
        X_numpy = X_tensor.numpy()
        num_sequences, sequence_length, num_features = X_numpy.shape
        flattened_data = X_numpy.reshape(num_sequences * sequence_length, num_features)

        # Define updated column names for DataFrame
        column_names = [
            'Packet_Length', 'TOS', 'TTL', 'Protocol', 'Source_Port', 'Destination_Port',
            'Window_Size', 'Payload_Length', 'TCP_Flags', 'Source_IP_Last_Octet', 
            'Destination_IP_Last_Octet', 'QoS_Awareness'
        ]
        df = pd.DataFrame(flattened_data, columns=column_names)

        # Repeat labels for each row in sequence
        labels_repeated = [label for label in labels for _ in range(sequence_length)]
        df['Label'] = labels_repeated

        # Set output CSV path by replacing .pt with .csv in the original filename
        csv_output_path = os.path.join(os.getcwd(), 'datasets', os.path.basename(pt_file_path).replace('.pt', '.csv'))
        df.to_csv(csv_output_path, index=False)
        
        print(f"Dataset saved as {csv_output_path}")
        return 0

    except Exception as e:
        print(f"An error occurred: {e}")
        return 1

# Main block to handle command-line argument
if __name__ == "__main__":
    pt_file = sys.argv[1] if len(sys.argv) > 1 else None
    status = pt_to_csv(pt_file)
    if status == 0:
        print("CSV file created successfully.")
    else:
        print("Failed to create CSV file.")
