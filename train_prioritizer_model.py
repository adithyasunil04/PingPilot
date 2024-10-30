import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import datetime
from os.path import isfile
from sys import argv
from torch.amp import GradScaler
from torch.amp import autocast
from os import name as OS_NAME



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
    scaler = GradScaler('cuda')
    
    for epoch in range(num_epochs):
        model.train()
        total_loss = 0
        for inputs, labels in train_loader:
            inputs, labels = inputs.to(device, non_blocking=True), labels.to(device, non_blocking=True)
            optimizer.zero_grad()
            
            with autocast("cuda"):
                outputs = model(inputs)
                loss = criterion(outputs, labels)
            
            scaler.scale(loss).backward()
            scaler.step(optimizer)
            scaler.update()
            
            total_loss += loss.item()
        
        print(f'Epoch [{epoch+1}/{num_epochs}], Loss: {total_loss/len(train_loader):.4f}')

def prepare_data(X, y):
    # Convert priorities to class indices (0-5)
    priority_to_class = {
        'Games': 0,
        'Real Time': 1,
        'Streaming': 2,
        'Normal': 3,
        'Web download': 4,
        'App download': 5
    }
    y_classes = torch.tensor([priority_to_class[p] for p in y])
    
    # Create DataLoader
    dataset = TensorDataset(X, y_classes)
    return DataLoader(dataset, batch_size=128, shuffle=True, pin_memory=True, num_workers=4)


def main(datasetName):
    
    if datasetName == None:
        while True:
            datasetName = input("Enter the dataset (.pt) file name (from datasets/ folder):")
            CAPTURE_DURATION = int(datasetName.split('_')[-1].split('.')[0])

            if OS_NAME=="posix":
                datasetName = "datasets/" + datasetName
            elif OS_NAME=="nt":
                datasetName = "datasets\\" + datasetName
            
            if isfile(datasetName) == False:
                print(f"File doesnt exist.{datasetName} Retry.")
            else:
                break
    



    # Check if CUDA is available
    device = torch.device("cuda")
    print(f"Using device: {device}")

    X, y = torch.load(datasetName, weights_only=True)
    
    # Prepare data
    train_loader = prepare_data(X, y)
    
    # Initialize the model and move it to GPU
    model = PacketPrioritizer().to(device)
    
    # Train the model
    train_model(model, train_loader, device)
    
      
    # Generate timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # updated PTH model's filename

    if OS_NAME == "posix":
        new_PTH_FILENAME = f"pthFiles/packet_prioritizer_{timestamp}_{CAPTURE_DURATION}.pth"
    elif OS_NAME == "nt":
        new_PTH_FILENAME = f"pthFiles\\packet_prioritizer_{timestamp}_{CAPTURE_DURATION}.pth"


    # Save the trained model
    torch.save(model.state_dict(), new_PTH_FILENAME)
    
    print("Model trained and saved successfully.")

if __name__ == "__main__":
    file = argv[1] if len(argv) > 1 else None
    main(file)