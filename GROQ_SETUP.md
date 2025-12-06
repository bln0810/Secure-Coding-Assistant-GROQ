# Groq AI Integration Setup Guide

## ✅ What You Get with Groq

- **Real AI-powered vulnerability analysis** (not just templates!)
- **Context-aware explanations** tailored to your specific code
- **Practical remediation examples** with secure code snippets
- **Fast inference** (usually < 1 second per vulnerability)
- **Generous free tier**: 30 requests/minute, 14,400 requests/day

---

## 🚀 Setup Steps (5 minutes)

### 1. Sign Up for Groq
- Go to: **https://console.groq.com**
- Click "Sign Up" (free, no credit card required)
- Verify your email

### 2. Get Your API Key
- Log in to Groq Console
- Navigate to **API Keys** section
- Click **"Create API Key"**
- Copy your key (starts with `gsk_...`)
- **Important**: Save it somewhere safe - you can't view it again!

### 3. Add to Your .env File
1. Open your `.env` file (or create it from `.env.example`)
2. Add your Groq API key:
   ```bash
   GROQ_API_KEY=gsk_your_actual_key_here
   ```
3. Save the file

### 4. Restart Your Flask Server
```bash
# Stop the current server (Ctrl+C)
python main/app.py
```

You should see:
```
Starting Secure Coding Assistant...
Debug mode: True
AI Analysis: Enabled  ← This confirms Groq is working!
Server running at: http://localhost:5000
```

---

## 🧪 Test It Out

1. Open http://localhost:5000 in your browser
2. Paste this vulnerable code:

```python
def login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    cursor.execute(query)
```

3. Click "Analyze Code"

### Without Groq (Template):
- Basic description: "String concatenation in SQL queries is dangerous"
- Generic suggestion: "Use parameterized queries"

### With Groq (AI-Enhanced):
- Detailed explanation of SQL injection attack vectors
- Specific examples of malicious inputs
- Step-by-step secure code implementation
- Context-aware suggestions based on your actual code

---

## 🔧 How It Works

```
Your Code → Security Analyzer (finds issues)
              ↓
         AI Analyzer (Groq API)
              ↓
    Enhanced vulnerability report with:
    - Detailed explanations
    - Attack scenarios
    - Secure code examples
    - Best practices
```

**Fallback**: If Groq API fails, automatically falls back to template-based enhancements.

---

## 📊 Rate Limits (Free Tier)

- **30 requests per minute**
- **14,400 requests per day**
- **Model**: Llama 3.3 70B (very capable!)

For your use case (analyzing code snippets), this is more than enough!

---

## ❓ Troubleshooting

### "AI Analysis: Disabled"
- ✅ Check that `GROQ_API_KEY` is set in `.env`
- ✅ Verify `.env` file is in the project root directory
- ✅ Restart the Flask server after adding the key

### "Groq API error: 401"
- ❌ Invalid API key
- ✅ Double-check you copied the full key from Groq Console
- ✅ Make sure there are no extra spaces

### "Groq API timeout"
- Network issue or API temporarily slow
- System automatically falls back to templates
- Try again in a few seconds

### Rate limit exceeded
- You've hit 30 requests/minute
- Wait 60 seconds and try again
- Or analyze fewer files at once

---

## 🆚 Groq vs HuggingFace

| Feature | Groq | HuggingFace (CodeBERT) |
|---------|------|------------------------|
| Text Generation | ✅ Yes | ❌ No (encoder only) |
| Speed | ⚡ Very Fast | 🐌 Slow |
| Free Tier | 🎁 Generous | 🎁 Limited |
| Setup | 🔧 Easy | 🔧 Easy |
| **Works for this app?** | ✅ **YES** | ❌ **NO** |

---

## 🎯 Next Steps

1. Get your Groq API key
2. Add it to `.env`
3. Restart server
4. Test with vulnerable code samples
5. Enjoy AI-powered security analysis! 🛡️

**Questions?** Check the console output for detailed error messages.
