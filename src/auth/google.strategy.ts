import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, Profile } from "passport-google-oauth20";
import { AuthService } from "./auth.service";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, "google") {
  constructor(private authService: AuthService) {
    const googleClientId = process.env.GOOGLE_CLIENT_ID;
    const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const googleCallbackUrl = process.env.GOOGLE_CALLBACK_URL;

    if (!googleClientId) {
      throw new Error("GOOGLE_CLIENT_ID is not defined in env");
    }
    if (!googleClientSecret) {
      throw new Error("GOOGLE_CLIENT_SECRET is not defined in env");
    }
    if (!googleCallbackUrl) {
      throw new Error("GOOGLE_CALLBACK_URL is not defined in env");
    }

    super({
      clientID: googleClientId,
      clientSecret: googleClientSecret,
      callbackURL: googleCallbackUrl,
      scope: ["email", "profile"],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    return this.authService.validateGoogleLogin(profile);
  }
}
