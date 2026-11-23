
import pandas as pd
import numpy as np
from pathlib import Path

def generate_dataset(records=10000):
    np.random.seed(42)

    user_ids = [f"USER_{i:04d}" for i in range(1, 501)]

    data = {
        "User_ID": np.random.choice(user_ids, records),
        "Email": [
            f"user{np.random.randint(1, 501)}@example.com"
            for _ in range(records)
        ],
        "IP_Address": [
            f"192.168.{np.random.randint(0, 256)}.{np.random.randint(1, 255)}"
            for _ in range(records)
        ],
        "Login_Hour": np.random.randint(0, 24, records),
        "Failed_Attempts": np.random.poisson(1, records),
        "Access_Type": np.random.choice(
            ["Web", "VPN", "SSH", "Database"], records
        ),
        "Device_Type": np.random.choice(
            ["Laptop", "Desktop", "Mobile", "Tablet"], records
        ),
        "Location": np.random.choice(
            ["India", "USA", "UK", "Germany", "Singapore"], records
        ),
    }

    df = pd.DataFrame(data)

    suspicious = (
        (df["Login_Hour"].between(0, 4)) |
        (df["Failed_Attempts"] >= 4) |
        ((df["Access_Type"] == "SSH") & (df["Location"] != "India"))
    )

    df["Status"] = suspicious.astype(int)

    output_path = Path(__file__).parent / "forensic_auth_logs.csv"
    df.to_csv(output_path, index=False)

    print("Synthetic forensic dataset generated successfully!")
    print(f"Total records: {len(df)}")
    print(f"Normal records: {(df['Status'] == 0).sum()}")
    print(f"Suspicious records: {(df['Status'] == 1).sum()}")
    print(f"Dataset saved at: {output_path}")

    print("\nDataset preview:")
    print(df.head())


if __name__ == "__main__":
    generate_dataset()
