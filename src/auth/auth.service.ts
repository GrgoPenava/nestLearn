import { Injectable, UnauthorizedException } from "@nestjs/common";
import { UserService } from "../user/user.service";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcrypt";
import { randomUUID } from "crypto";

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
  ) {}

  async register(email: string, password: string) {
    const existing = await this.userService.findByEmail(email);

    if (existing) {
      // Korisnik postoji ➜ provjeri ima li već passwordHash
      if (existing.passwordHash) {
        // Već ima password ➜ ne dozvoli ponovno registraciju
        throw new Error("Email already in use with password");
      }

      // NEMA passwordHash ➜ dozvoli mu da ga sad postavi!
      const hash = await bcrypt.hash(password, 10);
      await this.userService.setPassword(existing.id, hash);

      const tokens = await this.issueTokens(existing.id, existing.email);

      await this.userService.updateRefreshToken(
        existing.id,
        await bcrypt.hash(tokens.refreshToken, 10),
        tokens.jti,
      );

      return tokens;
    }

    // Ako korisnik ne postoji ➜ napravi novi
    const user = await this.userService.createUser(email, password);

    const tokens = await this.issueTokens(user.id, user.email);

    await this.userService.updateRefreshToken(
      user.id,
      await bcrypt.hash(tokens.refreshToken, 10),
      tokens.jti,
    );

    return tokens;
  }

  async validateUser(email: string, password: string) {
    const user = await this.userService.findByEmail(email);
    if (!user || !user.passwordHash)
      throw new UnauthorizedException("Invalid credentials");

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) throw new UnauthorizedException("Invalid credentials");

    return user;
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    const tokens = await this.issueTokens(user.id, user.email);

    await this.userService.updateRefreshToken(
      user.id,
      await bcrypt.hash(tokens.refreshToken, 10),
      tokens.jti,
    );

    return tokens;
  }

  async issueTokens(userId: number, email: string) {
    const jti = randomUUID();

    const accessToken = this.jwtService.sign(
      { sub: userId, email },
      { expiresIn: process.env.JWT_ACCESS_EXPIRATION },
    );

    const refreshToken = this.jwtService.sign(
      { sub: userId, type: "refresh", jti },
      { expiresIn: process.env.JWT_REFRESH_EXPIRATION },
    );

    return { accessToken, refreshToken, jti };
  }

  async refresh(userId: number, refreshToken: string) {
    let payload: any;
    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_SECRET,
      });
    } catch (e) {
      throw new UnauthorizedException("Invalid token signature");
    }

    if (payload.type !== "refresh" || payload.sub !== userId) {
      throw new UnauthorizedException("Invalid token payload");
    }

    const user = await this.userService.findById(userId);
    if (!user?.refreshTokenHash || !user?.refreshTokenJti) {
      throw new UnauthorizedException("No refresh token");
    }

    // Check bcrypt
    const isValid = await bcrypt.compare(refreshToken, user.refreshTokenHash);
    if (!isValid) {
      throw new UnauthorizedException("Invalid refresh token");
    }

    // ✅ Check JTI
    if (payload.jti !== user.refreshTokenJti) {
      throw new UnauthorizedException("Refresh token is revoked");
    }

    // Issue new tokens with new jti
    const tokens = await this.issueTokens(user.id, user.email);

    await this.userService.updateRefreshToken(
      user.id,
      await bcrypt.hash(tokens.refreshToken, 10),
      tokens.jti,
    );

    return tokens;
  }

  async validateGoogleLogin(profile: any) {
    const email = profile.emails[0].value;
    let user = await this.userService.findByEmail(email);

    if (!user) {
      user = await this.userService.createUser(email);
    } else if (!user.providerId) {
      await this.userService.setGoogleData(user.id, profile.id);
    }

    const tokens = await this.issueTokens(user.id, user.email);

    await this.userService.updateRefreshToken(
      user.id,
      await bcrypt.hash(tokens.refreshToken, 10),
      tokens.jti,
    );

    return tokens;
  }
}
