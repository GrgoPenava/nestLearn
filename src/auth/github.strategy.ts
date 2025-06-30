import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy, Profile } from "passport-github-oauth20";
import { AuthService } from "./auth.service";

@Injectable()
export class GithubStrategy extends PassportStrategy(Strategy, "github") {
  constructor(private authService: AuthService) {
    const githubClientId = process.env.GITHUB_CLIENT_ID;
    const githubClientSecret = process.env.GITHUB_CLIENT_SECRET;
    const githubCallbackUrl = process.env.GITHUB_CALLBACK_URL;

    if (!githubClientId) {
      throw new Error("GITHUB_CLIENT_ID is not defined in env");
    }
    if (!githubClientSecret) {
      throw new Error("GITHUB_CLIENT_SECRET is not defined in env");
    }
    if (!githubCallbackUrl) {
      throw new Error("GITHUB_CALLBACK_URL is not defined in env");
    }

    super({
      clientID: githubClientId,
      clientSecret: githubClientSecret,
      callbackURL: githubCallbackUrl,
      scope: ["user:email"],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    return this.authService.validateGithubLogin(profile, accessToken);
  }
}
