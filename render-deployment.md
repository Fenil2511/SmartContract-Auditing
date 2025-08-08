# Render Deployment Guide

## Step 1: Prepare Your Repository

Make sure your repository structure looks like this:
```
SmartContract-Auditing/
├── backend/
│   ├── server.py
│   ├── audit_engine.py
│   ├── requirements.txt
│   └── start.sh
├── frontend/
│   └── ...
└── render.yaml
```

## Step 2: Deploy to Render

1. **Go to [Render](https://render.com/)**
2. **Sign up/Login with GitHub**
3. **Click "New +" → "Web Service"**
4. **Connect your GitHub repository**
5. **Configure the service:**

   **Basic Settings:**
   - **Name:** `smart-contract-auditor-backend`
   - **Environment:** `Python`
   - **Region:** Choose closest to you
   - **Branch:** `main` (or your default branch)

   **Build & Deploy Settings:**
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn server:app --host 0.0.0.0 --port $PORT`

6. **Click "Create Web Service"**

## Step 3: Set Environment Variables

After creating the service, go to the **Environment** tab and add:

```
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net
DB_NAME=smart_contract_auditor
```

**For MongoDB Atlas:**
1. Go to [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Create free account
3. Create cluster
4. Get connection string
5. Replace `username:password` with your credentials

## Step 4: Test Your Deployment

After deployment, test these URLs:

1. **Health check:** `https://your-app-name.onrender.com/api/`
2. **Test analysis:** `https://your-app-name.onrender.com/api/test`

## Troubleshooting

### If you get "ModuleNotFoundError":

1. **Check Root Directory:** Make sure it's set to `backend`
2. **Check Start Command:** Should be `uvicorn server:app --host 0.0.0.0 --port $PORT`
3. **Check Build Command:** Should be `pip install -r requirements.txt`

### If MongoDB connection fails:

1. **Use MongoDB Atlas** instead of local MongoDB
2. **Check connection string** format
3. **Whitelist Render IPs** in MongoDB Atlas

### If port issues:

1. **Use `$PORT`** environment variable (not hardcoded)
2. **Don't use port 10000** in production

## Update Frontend

After getting your Render URL, update your Netlify environment variable:

```
REACT_APP_BACKEND_URL=https://your-app-name.onrender.com
``` 