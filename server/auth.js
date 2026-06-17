const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { Strategy: LocalStrategy } = require('passport-local');

/**
 * Authentication and Authorization Module
 * Handles user authentication, session management, and role-based access control
 * Using Passport.js with JWT tokens
 */

// JWT Secret - In production, use environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'nodecast-tv-secret-key-change-in-production';
const JWT_EXPIRY = '24h';

/**
 * Hash password using bcrypt
 */
async function hashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(password, salt);
}

/**
 * Verify password against hash
 */
async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

/**
 * Generate JWT token
 */
function generateToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username,
            role: user.role
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
    );
}

/**
 * Verify JWT token
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return null;
    }
}

/**
 * Configure Passport Local Strategy for username/password authentication
 */
function configureLocalStrategy(getUserByUsername, verifyUserPassword) {
    passport.use(new LocalStrategy(
        async (username, password, done) => {
            try {
                const user = await getUserByUsername(username);

                if (!user) {
                    return done(null, false, { message: 'Invalid credentials' });
                }

                const isValid = await verifyUserPassword(password, user.passwordHash);

                if (!isValid) {
                    return done(null, false, { message: 'Invalid credentials' });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    ));
}

/**
 * Configure Passport JWT Strategy for token-based authentication
 */
function configureJwtStrategy(getUserById) {
    const options = {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: JWT_SECRET
    };

    passport.use(new JwtStrategy(options, async (payload, done) => {
        try {
            const user = await getUserById(payload.id);

            if (!user) {
                return done(null, false);
            }

            return done(null, {
                id: user.id,
                username: user.username,
                role: user.role
            });
        } catch (err) {
            return done(err, false);
        }
    }));
}

/**
 * Configure Passport session serialization
 * Required for OIDC flow which uses sessions
 */
function configureSessionSerialization(getUserById) {
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await getUserById(id);
            done(null, user);
        } catch (err) {
            done(err, null);
        }
    });
}

/**
 * Fetch OIDC endpoints from the provider's discovery document.
 * Falls back to manually specified env vars if present.
 * Works with any standard OIDC provider (Authentik, Keycloak, Okta, etc.)
 *
 * @param {string} issuerUrl - The OIDC issuer URL (e.g. https://auth.example.com/application/o/myapp/)
 * @returns {Promise<{authorizationURL, tokenURL, userInfoURL}>}
 */
async function discoverOidcEndpoints(issuerUrl) {
    // Allow manual overrides via env vars (useful for non-standard providers)
    if (process.env.OIDC_AUTH_URL && process.env.OIDC_TOKEN_URL && process.env.OIDC_USERINFO_URL) {
        console.log('[OIDC] Using manually specified endpoint URLs from environment variables');
        return {
            authorizationURL: process.env.OIDC_AUTH_URL,
            tokenURL: process.env.OIDC_TOKEN_URL,
            userInfoURL: process.env.OIDC_USERINFO_URL,
        };
    }

    // Build the discovery URL: strip trailing slash, append well-known path
    const base = issuerUrl.replace(/\/$/, '');
    const discoveryUrl = `${base}/.well-known/openid-configuration`;

    console.log(`[OIDC] Fetching discovery document from: ${discoveryUrl}`);

    const res = await fetch(discoveryUrl);
    if (!res.ok) {
        throw new Error(`[OIDC] Discovery failed: HTTP ${res.status} from ${discoveryUrl}`);
    }

    const config = await res.json();

    const authorizationURL = config.authorization_endpoint;
    const tokenURL = config.token_endpoint;
    const userInfoURL = config.userinfo_endpoint;

    if (!authorizationURL || !tokenURL || !userInfoURL) {
        throw new Error(
            `[OIDC] Discovery document from ${discoveryUrl} is missing required endpoints. ` +
            `Got: authorization_endpoint=${authorizationURL}, token_endpoint=${tokenURL}, userinfo_endpoint=${userInfoURL}`
        );
    }

    console.log(`[OIDC] Discovery successful:`);
    console.log(`  authorization_endpoint: ${authorizationURL}`);
    console.log(`  token_endpoint:         ${tokenURL}`);
    console.log(`  userinfo_endpoint:      ${userInfoURL}`);

    return { authorizationURL, tokenURL, userInfoURL };
}

/**
 * Configure Passport OpenID Connect Strategy.
 * Automatically discovers provider endpoints via the OIDC discovery document,
 * so it works with any standard provider (Authentik, Keycloak, Okta, etc.)
 * without hardcoding provider-specific URL paths.
 */
async function configureOidcStrategy(findUserByOidcId, findUserByEmail, createUser) {
    if (!process.env.OIDC_ISSUER_URL || !process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET) {
        console.warn('[OIDC] Configuration missing (OIDC_ISSUER_URL / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET) - SSO disabled');
        return;
    }

    const { Strategy: OpenIDConnectStrategy } = require('passport-openidconnect');

    // Discover endpoints from the provider's .well-known/openid-configuration
    const { authorizationURL, tokenURL, userInfoURL } = await discoverOidcEndpoints(process.env.OIDC_ISSUER_URL);

    passport.use(new OpenIDConnectStrategy({
        issuer: process.env.OIDC_ISSUER_URL,
        authorizationURL,
        tokenURL,
        userInfoURL,
        clientID: process.env.OIDC_CLIENT_ID,
        clientSecret: process.env.OIDC_CLIENT_SECRET,
        callbackURL: process.env.OIDC_CALLBACK_URL || '/api/auth/oidc/callback',
        scope: (process.env.OIDC_SCOPES || 'openid profile email').split(' ')
    },
        async (...args) => {
            // The done callback is always the last argument
            const done = args[args.length - 1];

            // Map known arguments
            // Standard: issuer, sub, profile, accessToken, refreshToken, done
            // Some versions: issuer, sub, profile, accessToken, refreshToken, params, done

            let issuer, sub, profile;

            if (args.length === 3) {
                // Scenario: (issuer, profile, done)
                const arg0 = args[0];
                const arg1 = args[1];

                if (typeof arg1 === 'object' && arg1.id) {
                    issuer = arg0;
                    profile = arg1;
                    sub = profile.id;
                } else if (typeof arg0 === 'string' && typeof arg1 === 'string') {
                    issuer = arg0;
                    sub = arg1;
                    profile = { id: sub, displayName: 'Unknown' };
                }
            } else if (args.length >= 4) {
                // Assume standard: iss, sub, profile...
                issuer = args[0];
                sub = args[1];
                profile = args[2];
            }

            if (!sub && profile && profile.id) sub = profile.id;

            if (!sub) {
                return done(new Error('Could not identify OIDC Subject (sub) from arguments'));
            }

            try {
                // 1. Try to find by OIDC ID (sub)
                let user = await findUserByOidcId(sub);

                // 2. If not found, try to match by email
                // Extract email - handle both profile.emails[] (Google) and profile.email (others)
                const email = profile.emails?.[0]?.value || profile.email || profile._json?.email;

                if (!user && email) {
                    user = await findUserByEmail(email);

                    // If found by email but no OIDC ID, link them
                    if (user && !user.oidcId) {
                        // We don't have a direct update method for specific fields without full user object in this context
                        // Ideally we'd update the user here. For now, we'll just log in.
                        // Future: Update user with oidcId
                    }
                }

                // 3. If still not found, create new user (JIT Provisioning)
                if (!user) {
                    const username = profile.username || profile.displayName || (email ? email.split('@')[0] : `user_${sub.substring(0, 8)}`);

                    user = await createUser({
                        username: username,
                        role: 'viewer', // Default role for SSO users
                        oidcId: sub,
                        email: email || null
                    });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }));
}

/**
 * Middleware: Require authentication using Passport JWT
 */
const requireAuth = passport.authenticate('jwt', { session: false });

/**
 * Middleware: Require admin role
 */
function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden - Admin access required' });
    }
    next();
}

/**
 * Middleware: Check for specific role
 */
function requireRole(role) {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: `Forbidden - ${role} access required` });
        }
        next();
    };
}

module.exports = {
    passport,
    hashPassword,
    verifyPassword,
    generateToken,
    verifyToken,
    configureLocalStrategy,
    configureJwtStrategy,
    configureSessionSerialization,
    configureOidcStrategy,
    requireAuth,
    requireAdmin,
    requireRole
};
