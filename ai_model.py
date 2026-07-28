from sklearn.ensemble import IsolationForest

# ======================================
# AI TRAINING DATA
# CPU, RAM, Download Speed, Upload Speed
# ======================================

training_data = [

    [20, 30, 100, 50],
    [25, 35, 120, 60],
    [30, 40, 150, 70],
    [35, 45, 180, 80],
    [40, 50, 220, 90],
    [45, 55, 250, 100],
    [50, 60, 300, 120]

]

# ======================================
# CREATE AI MODEL
# ======================================

model = IsolationForest(
    contamination=0.10,
    random_state=42
)

# Train the model
model.fit(training_data)

# ======================================
# AI DETECTION FUNCTION
# ======================================

def detect_anomaly(cpu, ram, download, upload):

    sample = [[
        cpu,
        ram,
        download,
        upload
    ]]

    prediction = model.predict(sample)

    if prediction[0] == -1:

        return {
            "status": "Suspicious",
            "message": "⚠️ Unusual network behaviour detected."
        }

    else:

        return {
            "status": "Safe",
            "message": "✅ Network behaviour is normal."
        }


# ======================================
# TEST (Runs only when this file is
# executed directly)
# ======================================

if __name__ == "__main__":

    result = detect_anomaly(
        cpu=35,
        ram=45,
        download=180,
        upload=80
    )

    print("AI Status :", result["status"])
    print("Message   :", result["message"])