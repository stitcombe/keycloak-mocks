const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware to parse POST data
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Handle SAML ACS POST callback
app.post('/acs', (req, res) => {
    const { SAMLResponse, RelayState } = req.body;
    
    // Redirect to index.html with SAML data as query parameters
    if (SAMLResponse) {
        const params = new URLSearchParams({
            SAMLResponse,
            ...(RelayState && { RelayState })
        });
        res.redirect(`/?${params.toString()}`);
    } else {
        res.redirect('/');
    }
});

// Handle GET requests to /acs (for testing)
app.get('/acs', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`SAML SP test server running on port ${PORT}`);
});