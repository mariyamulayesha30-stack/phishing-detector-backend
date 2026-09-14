
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import pandas as pd

app = Flask(__name__)
CORS(app)

with open('phishing_model.pkl', 'rb') as f:
    model2 = pickle.load(f)

selected_features = ['having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'HTTPS_token', 'Abnormal_URL', 'Redirect', 'port', 'SSLfinal_State']

def extract_features(url):
    features = {}
    domain = url.split('/')[2] if len(url.split('/')) > 2 else url
    features['having_IPhaving_IP_Address'] = -1 if any(char.isdigit() for char in domain.split('.')[0]) else 1
    features['URLURL_Length'] = 1 if len(url) < 54 else (0 if len(url) <= 75 else -1)
    features['Shortining_Service'] = -1 if ('bit.ly' in url or 'tinyurl' in url) else 1
    features['having_At_Symbol'] = -1 if '@' in url else 1
    features['double_slash_redirecting'] = -1 if url.rfind('//') > 7 else 1
    features['Prefix_Suffix'] = -1 if '-' in domain else 1
    features['having_Sub_Domain'] = 1 if url.count('.') <= 2 else (0 if url.count('.') == 3 else -1)
    features['HTTPS_token'] = -1 if not url.startswith('https') else 1
    suspicious_words = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'confirm', 'free', 'gift', 'claim', 'prize', 'winner', 'urgent']
    features['Abnormal_URL'] = -1 if any(word in url.lower() for word in suspicious_words) else 1
    features['Redirect'] = -1 if url.count('-') > 2 else 0
    suspicious_tld = ['.tk', '.ml', '.ga', '.cf', '.gq']
    features['port'] = -1 if any(url.endswith(tld) or tld+'/' in url for tld in suspicious_tld) else 1
    features['SSLfinal_State'] = 1 if url.startswith('https') else -1
    return features

@app.route('/predict', methods=['POST'])
def predict():
    data_in = request.get_json()
    url = data_in.get('url', '')
    features = extract_features(url)
    suspicious_count = sum(1 for v in features.values() if v == -1)
    feature_df = pd.DataFrame([features])[selected_features]
    ml_phishing_prob = model2.predict_proba(feature_df)[0][0] * 100
    final_score = (ml_phishing_prob + (suspicious_count/12*100)) / 2
    if features['having_IPhaving_IP_Address'] == -1:
        final_score = max(final_score, 75)
    if features['Shortining_Service'] == -1:
        final_score = max(final_score, 55)
    result = "PHISHING" if final_score > 45 else "SAFE"
    return jsonify({'url': url, 'score': round(final_score, 2), 'result': result})

@app.route('/', methods=['GET'])
def home():
    return "Phishing Detection API is running"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
