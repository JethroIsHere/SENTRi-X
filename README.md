# SENTRi-X: Cross-Domain Hybrid Intrusion Detection System

SENTRi-X is an adaptive, Explainable AI (XAI)-powered Intrusion Detection System. It leverages a Hybrid Ensemble Engine—fusing the high-speed tabular precision of Random Forests with the spatial feature extraction of Convolutional Neural Networks (CNNs). 

Designed to protect heterogeneous network architectures, SENTRi-X natively defends modern IoT environments and utilizes Transfer Learning to adapt its defense mechanisms to legacy botnets and large-scale Enterprise IT networks.

## 🚀 Key Highlights

* **Omni Global Defense Mode:** Fuses ToN-IoT, BoT-IoT, and CIC-IDS2017 datasets into a single, massive universal model capable of defending against IoT botnets, legacy malware, and modern Enterprise IT exploits simultaneously.
* **Hybrid Ensemble Core:** Combines RF and CNN architectures for robust flow-based network traffic analysis.
* **Cross-Domain Adaptation:** Proves that an AI trained on modern IoT traffic (ToN-IoT) can successfully protect distinct environments using only a 20% transfer learning sample:
  * **BoT-IoT (2018 Botnets):** Achieved **99.98%** accuracy.
  * **CIC-IDS2017 (Enterprise IT):** Achieved **98.14%** accuracy.
* **Explainable AI (Glass-Box):** Integrates SHAP (force plots), LIME (local surrogate weights), and semantic, plain-English security heuristics extracted from RIPPER to ensure all AI mitigation decisions are transparent and human-readable.

---

## 📂 Project Structure & Methodology

The repository is structured sequentially to follow the exact research methodology, starting from baseline training to final cross-domain evaluation.

### Phase 1: Native Baseline (ToN-IoT Environment)
* `01_ETL_Pipeline_ToN_IoT.ipynb` - Data extraction, cleaning, and domain-specific scaling for the baseline dataset.
* `02_Model_Training_RF_ToN_IoT.ipynb` - Core Random Forest training and threshold optimization.
* `03_Model_Training_CNN_ToN_IoT.ipynb` - Spatial feature extraction model training.
* `04_Hybrid_Ensemble_Fusion_ToN_IoT.ipynb` - Fusing RF and CNN predictions for the final ToN-IoT baseline metrics.
* `05_Explainable_AI_ToN_IoT.ipynb` - Implementation of SHAP, LIME, and RIPPER rule extraction.

### Phase 2: Zero-Shot Evaluation & Universal Schema
* `06_Universal_Schema_Mapper.ipynb` - Standardizing disparate dataset features (BoT-IoT, CIC-IDS2017) into the baseline ToN-IoT matrix shape.
* `07_Cross_Validation_BoT_IoT.ipynb` - Proving the limitations of zero-shot cross-domain generalization.

### Phase 3: Transfer Learning (Domain Adaptation)
* `01_ETL_Pipeline_BoT_IoT.ipynb` - Specific data scaling and engineering for Botnet traffic.
* `08_Transfer_Learning_BoT_IoT.ipynb` - Recalibrating the hybrid engine via Domain Adaptation (99.98% accuracy).
* `01_ETL_Pipeline_CIC_IDS2017.ipynb` - Specific data scaling and engineering for Enterprise IT traffic.
* `09_Transfer_Learning_CIC_IDS2017.ipynb` - The final transfer learning evaluation on the CIC-IDS2017 dataset (98.14% accuracy).

### Phase 4: The Omni Global Pipeline
* `10_Omni_Model_Training.ipynb` - Combines 150,000 samples across all three datasets to forge `rf_model_omni.joblib` and `cnn_model_omni.h5`, feeding the dashboard's overarching "Omni Defense Mode."

---

## 💻 Running the Intercative Dashboard

SENTRi-X features a full-stack React and FastAPI dashboard to simulate live traffic inference. Because the engine processes heavy TensorFlow dependencies, **you must start the backend from within the virtual environment.**

### 1. Start the FastAPI Backend (Terminal 1)
Open a terminal and activate the virtual environment so the Python engine can load the models correctly:
```bash
# Navigate to project root
cd SENTRi-X

# Activate the Virtual Environment (Windows)
venv\Scripts\activate
# OR on Linux/Mac: source venv/bin/activate

# Navigate to backend and start the Uvicorn server
cd backend
python -m uvicorn main:app
```
*Wait until the terminal outputs:* `Application startup complete.`

### 2. Start the React Frontend (Terminal 2)
Open a **second** terminal to host the UI:
```bash
cd SENTRi-X/frontend
npm run dev
```
Navigate to `http://localhost:5173` in your browser. The dashboard will automatically connect to the backend, populate the XAI rules, and begin streaming live, concatenated global IoT/Enterprise traffic.

---

## 🛠️ Installation & Setup (For Training)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/sentri-x.git
   cd sentri-x
   ```

2. **Create a virtual environment:**
    ```bash
    python -m venv venv
    venv\Scripts\activate  # On Windows
    ```

3. **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

*Note: The raw PCAP/CSV datasets (ToN-IoT, BoT-IoT, CIC-IDS2017) are excluded from this repository due to size constraints. To reproduce the training notebooks, download the respective datasets and place them in a local `data/raw/` directory.*

