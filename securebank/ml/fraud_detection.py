# SecureBank Fraud Detection ML Demo
# This script uses a basic machine learning classification model
# to detect suspicious banking transactions using synthetic data.

import pandas as pd
from sklearn.tree import DecisionTreeClassifier


# ------------------------------------------------
# 1. Create synthetic training data
# ------------------------------------------------
# 0 = Normal
# 1 = Suspicious

training_data = pd.DataFrame({
    "amount": [
        10, 20, 35, 50, 75, 100, 150, 200, 250, 300,
        500, 600, 700, 850, 900, 1000
    ],
    "transfers_last_hour": [
        1, 1, 1, 1, 2, 2, 2, 2, 2, 3,
        3, 4, 5, 4, 5, 6
    ],
    "failed_logins_24h": [
        0, 0, 0, 0, 0, 1, 0, 1, 0, 1,
        1, 2, 3, 2, 3, 4
    ],
    "hour_of_day": [
        9, 10, 11, 12, 13, 14, 15, 16, 18, 17,
        18, 21, 23, 2, 3, 1
    ],
    "label": [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1
    ]
})


# ------------------------------------------------
# 2. Create test transactions
# ------------------------------------------------

test_data = pd.DataFrame({
    "transaction_name": [
        "Small normal transfer",
        "SecureBank Test1 transfer",
        "Large SecureBank transfer",
        "Very large late-night transfer",
        "Multiple transfers after failed logins"
    ],
    "amount": [50, 250, 500, 900, 700],
    "transfers_last_hour": [1, 2, 2, 4, 5],
    "failed_logins_24h": [0, 0, 0, 2, 3],
    "hour_of_day": [11, 18, 18, 2, 23]
})


# ------------------------------------------------
# 3. Train the ML model
# ------------------------------------------------

features = ["amount", "transfers_last_hour", "failed_logins_24h", "hour_of_day"]

model = DecisionTreeClassifier(random_state=42)
model.fit(training_data[features], training_data["label"])


# ------------------------------------------------
# 4. Make predictions
# ------------------------------------------------

predictions = model.predict(test_data[features])

test_data["ml_prediction"] = predictions
test_data["fraud_status"] = test_data["ml_prediction"].apply(
    lambda x: "Suspicious" if x == 1 else "Normal"
)


# ------------------------------------------------
# 5. Show results
# ------------------------------------------------

print("\nSecureBank ML Fraud Detection Results")
print("------------------------------------")

for index, row in test_data.iterrows():
    print(f"Transaction: {row['transaction_name']}")
    print(f"Amount: £{row['amount']}")
    print(f"Transfers Last Hour: {row['transfers_last_hour']}")
    print(f"Failed Logins 24h: {row['failed_logins_24h']}")
    print(f"Hour of Day: {row['hour_of_day']}")
    print(f"ML Fraud Status: {row['fraud_status']}")
    print("------------------------------------")


# ------------------------------------------------
# 6. Save results to CSV
# ------------------------------------------------

test_data.to_csv("fraud_detection_results.csv", index=False)

print("\nResults saved to fraud_detection_results.csv")