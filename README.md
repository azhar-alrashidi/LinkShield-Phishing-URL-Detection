# 🛡 LinkShield

A machine-learning web app that detects phishing URLs. Paste a link and get an instant **SAFE / MALICIOUS** verdict, a technical analysis of why, and a downloadable PDF report.

![Scan page](screenshots/scan.png)

## Features

- **Random Forest classifier** trained on 36 lexical features extracted from the URL (length, entropy, digit ratio, risky TLDs, IP addresses, `@` tricks, shorteners, and more)
- **Input validation** rejects text that is not a valid URL
- **Explainable results**: human-readable red flags next to the ML verdict
- **PDF scan reports** generated on the fly
- **Session history** for each visitor
- **Admin dashboard** (login protected) with scan statistics, filtering, and a SQLite scan log
- Responsive dark UI

## Tech stack

Python · Flask · scikit-learn · pandas · SQLAlchemy (SQLite) · fpdf2

## Results

| Metric | Value |
|--------|-------|
| Model | Random Forest (100 trees, depth 15) |
| Test accuracy | **91.48%** |
| Features | 36 |

## Dataset

The model was trained on a merged dataset compiled from three public sources:

1. [SOURCE 1 NAME](LINK) - short description
2. [SOURCE 2 NAME](LINK) - short description
3. [SOURCE 3 NAME](LINK) - short description

Preprocessing: duplicates removed, URLs cleaned and validated, safe class undersampled to balance the classes.
The merged dataset is available on Kaggle: [LINK].

> The dataset is not included in this repo because of its size. Download it and save it as `data/phishing_site_urls.csv`.

## Getting started

```bash
git clone https://github.com/YOUR_USERNAME/LinkShield.git
cd LinkShield
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 1. Train the model (needs data/phishing_site_urls.csv)
python models/train.py

# 2. Configure secrets
cp .env.example .env        # then edit SECRET_KEY and ADMIN_PASSWORD

# 3. Run
python app.py
```

Open http://127.0.0.1:5000. The admin dashboard is at `/admin` (disabled until `ADMIN_PASSWORD` is set).

## Project structure

```
LinkShield/
├── app.py              # Flask app: routes, prediction, PDF, admin
├── models/
│   ├── analyze.py      # Feature extraction (36 features)
│   ├── train.py        # Model training and evaluation
│   └── data_info.py    # Dataset inspection helper
├── templates/          # HTML templates
├── data/               # Place the dataset here
└── requirements.txt
```

## Limitations

- The model analyses the **URL string only**, not page content, domain age, or WHOIS data, so it can miss well-crafted phishing URLs and flag unusual-but-legit ones.
- The model evaluates URL structure only; it cannot verify whether a domain exists or is reputable.
- Accuracy depends on the training data, which reflects the phishing patterns of its time.
- Use it as a first-line signal, not as a replacement for security judgment.

## License

MIT - see [LICENSE](LICENSE).
