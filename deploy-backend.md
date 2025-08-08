# Backend Deployment Guide

## Quick Deploy to Railway

1. **Install Railway CLI:**
   ```bash
   npm install -g @railway/cli
   ```

2. **Login to Railway:**
   ```bash
   railway login
   ```

3. **Deploy from backend directory:**
   ```bash
   cd backend
   railway init
   railway up
   ```

4. **Set environment variables in Railway dashboard:**
   ```
   MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net
   DB_NAME=smart_contract_auditor
   ```

## Alternative: Deploy to Render

1. **Go to [Render](https://render.com/)**
2. **Create new Web Service**
3. **Connect your GitHub repository**
4. **Configure:**
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. **Set environment variables**
6. **Deploy**

## Test Your Backend

After deployment, test these endpoints:

1. **Health check:** `https://your-backend-url/api/`
2. **Test analysis:** `https://your-backend-url/api/test`

## Troubleshooting

### If you get "Analysis failed" error:

1. **Check backend logs** in your deployment platform
2. **Test the backend directly** using the test endpoint
3. **Verify environment variables** are set correctly
4. **Check if MongoDB is accessible** from your deployment platform

### Common Issues:

1. **MongoDB connection failed:**
   - Use MongoDB Atlas (cloud) instead of local MongoDB
   - Check your connection string format
   - Ensure IP whitelist includes your deployment platform

2. **Python dependencies missing:**
   - Make sure `requirements.txt` is in the backend directory
   - Check if all dependencies are compatible

3. **Port issues:**
   - Use `$PORT` environment variable in start command
   - Don't hardcode port numbers

## Environment Variables

Required environment variables:
```
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net
DB_NAME=smart_contract_auditor
```

## Update Frontend

After getting your backend URL, update your frontend environment variable:
```
REACT_APP_BACKEND_URL=https://your-backend-url.railway.app
``` 