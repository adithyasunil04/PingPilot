import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from os.path import isfile
from os import name as OS_NAME
import datetime
from sys import argv

# globals
PTH_FILENAME = None
newDatasetName = None
CAPTURE_DURATION = None

class PacketPrioritizer(nn.Module):
    def __init__(self):
        super().__init__()
        self.lstm = nn.LSTM(input_size=10, hidden_size=64, num_layers=2, batch_first=True)
        self.fc1 = nn.Linear(64, 32)
        self.fc2 = nn.Linear(32, 6)  # 6 output classes for 6 priority levels
        self.relu = nn.ReLU()

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        x = self.relu(self.fc1(lstm_out[:, -1, :]))
        return self.fc2(x)

def train_model(model, train_loader, device, num_epochs=50):
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters())

    for epoch in range(num_epochs):
        model.train()
        total_loss = 0
        for inputs, labels in train_loader:
            inputs, labels = inputs.to(device), labels.to(device)
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        print(f'Epoch [{epoch+1}/{num_epochs}], Loss: {total_loss/len(train_loader):.4f}')

def prepare_data(X, y):
    priority_to_class = {
        'Games': 0,
        'Real Time': 1,
        'Streaming': 2,
        'Normal': 3,
        'Web download': 4,
        'App download': 5
    }
    y_classes = torch.tensor([priority_to_class[p] for p in y])
    dataset = TensorDataset(X, y_classes)
    return DataLoader(dataset, batch_size=32, shuffle=True)

def main(pth_file, datasetName):
    global PTH_FILENAME, newDatasetName, CAPTURE_DURATION

    if pth_file is None and datasetName is None:
        while True:
            if PTH_FILENAME is None:
                PTH_FILENAME = input("Enter the previously trained model (.pth) file name (from pthFiles/ folder): ")
            if newDatasetName is None:
                newDatasetName = input("Enter the training dataset (.pt) file name (from datasets/ folder): ")
            
            if OS_NAME=="posix":
                newDatasetName = "datasets/" + newDatasetName
                PTH_FILENAME = "pthFiles/" + PTH_FILENAME
            elif OS_NAME=="nt":
                newDatasetName = "datasets\\" + newDatasetName
                PTH_FILENAME = "pthFiles\\" + PTH_FILENAME
            
            
            if isfile(PTH_FILENAME) and isfile(newDatasetName):
                break
            else:
                print("File(s) doesn't exist. Retry.")

         

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load the pre-trained model
    model = PacketPrioritizer()
    model.load_state_dict(torch.load(PTH_FILENAME))
    model.to(device)
    print("Pre-trained model loaded successfully.")

    # Load the new dataset
    X, y, CAPTURE_DURATION = torch.load(newDatasetName)

    # Prepare data
    train_loader = prepare_data(X, y)

    # Train the model again
    print("Starting additional training...")
    train_model(model, train_loader, device)

    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Update the filename based on the requirements
    existing_capture_duration = int(PTH_FILENAME.split('_')[-1].split('.')[0])
    new_capture_duration = existing_capture_duration + int(CAPTURE_DURATION)
#    new_PTH_FILENAME = f"packet_prioritizer_{timestamp}_{new_capture_duration}.pth"

    if OS_NAME == "posix":
        new_PTH_FILENAME = f"pthFiles/packet_prioritizer_{timestamp}_{CAPTURE_DURATION}.pth"
    elif OS_NAME == "nt":
        new_PTH_FILENAME = f"pthFiles\\packet_prioritizer_{timestamp}_{CAPTURE_DURATION}.pth"

    # Save the updated model
    torch.save(model.state_dict(), new_PTH_FILENAME)

    print(f"Model retrained and saved successfully as {new_PTH_FILENAME}")

if __name__ == "__main__":
    file1, file2 = (None, None) if len(argv) < 2 else (argv[1], argv[2])
    main(file1, file2)