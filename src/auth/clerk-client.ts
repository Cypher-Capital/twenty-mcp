import { createClerkClient } from '@clerk/clerk-sdk-node';
import type { ClerkClient as ClerkSDKClient } from '@clerk/clerk-sdk-node';

export interface TokenValidationResult {
  valid: boolean;
  userId?: string;
  sessionId?: string;
  error?: string;
}

export interface UserMetadata {
  twentyApiKey?: string;
  twentyBaseUrl?: string;
  twentyApiKeyUpdatedAt?: string;
}

export class ClerkClient {
  private clerk: ClerkSDKClient;
  private enabled: boolean;
  
  constructor() {
    this.enabled = process.env.AUTH_ENABLED === 'true';
    
    if (this.enabled) {
      const secretKey = process.env.CLERK_SECRET_KEY;
      const publishableKey = process.env.CLERK_PUBLISHABLE_KEY;
      
      if (!secretKey) {
        throw new Error('CLERK_SECRET_KEY is required when AUTH_ENABLED=true');
      }
      
      this.clerk = createClerkClient({
        secretKey,
        publishableKey,
      });
    } else {
      // Create a dummy client for when auth is disabled
      this.clerk = null as any;
    }
  }
  
  isEnabled(): boolean {
    return this.enabled;
  }
  
  async validateToken(token: string): Promise<TokenValidationResult> {
    if (!this.enabled) {
      return { valid: false, error: 'Authentication is not enabled' };
    }

    try {
      const cleanToken = token.replace(/^Bearer\s+/i, '');

      // Path 1: Clerk session JWT — three-part JWT with a `sid` claim pointing
      // at an active Clerk session. This is the shape Clerk's frontend SDKs issue.
      const tokenParts = cleanToken.split('.');
      if (tokenParts.length === 3) {
        try {
          const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64url').toString());
          if (payload.sid) {
            const session = await this.clerk.sessions.getSession(payload.sid);
            if (!session || session.status !== 'active') {
              return { valid: false, error: 'Invalid or inactive session' };
            }
            return {
              valid: true,
              userId: session.userId,
              sessionId: session.id,
            };
          }
        } catch {
          // Not a Clerk session JWT; fall through to OAuth validation.
        }
      }

      // Path 2: OAuth 2.0 access token (issued to third-party clients via
      // authorization_code grant, e.g. claude.ai's MCP connector). These are
      // not Clerk sessions; validate by calling Clerk's userinfo endpoint.
      const clerkDomain = process.env.CLERK_DOMAIN;
      if (!clerkDomain) {
        return { valid: false, error: 'CLERK_DOMAIN not configured' };
      }

      const userinfoResponse = await fetch(`https://${clerkDomain}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${cleanToken}` },
      });

      if (!userinfoResponse.ok) {
        return {
          valid: false,
          error: `OAuth token rejected by Clerk (HTTP ${userinfoResponse.status})`,
        };
      }

      const userInfo = (await userinfoResponse.json()) as {
        user_id?: string;
        sub?: string;
      };
      const userId = userInfo.user_id || userInfo.sub;
      if (!userId) {
        return { valid: false, error: 'No user ID in OAuth userinfo response' };
      }

      return {
        valid: true,
        userId,
        sessionId: 'oauth-access-token',
      };
    } catch (error) {
      console.error('Token validation error:', error);
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Token validation failed',
      };
    }
  }
  
  async getUserMetadata(userId: string): Promise<UserMetadata | null> {
    if (!this.enabled) {
      return null;
    }
    
    try {
      const user = await this.clerk.users.getUser(userId);
      return user.privateMetadata as UserMetadata || {};
    } catch (error) {
      console.error('Failed to get user metadata:', error);
      return null;
    }
  }
  
  async updateUserMetadata(userId: string, metadata: UserMetadata): Promise<void> {
    if (!this.enabled) {
      throw new Error('Authentication is not enabled');
    }
    
    try {
      await this.clerk.users.updateUser(userId, {
        privateMetadata: metadata as any,
      });
    } catch (error) {
      console.error('Failed to update user metadata:', error);
      throw new Error('Failed to update user configuration');
    }
  }
  
  getClerkDomain(): string {
    return process.env.CLERK_DOMAIN || '';
  }
  
  getPublishableKey(): string {
    return process.env.CLERK_PUBLISHABLE_KEY || '';
  }
}