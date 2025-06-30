import { Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import * as bcrypt from "bcrypt";

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async createUser(email: string, password?: string) {
    const hash = password ? await bcrypt.hash(password, 10) : null;
    return this.prisma.user.create({
      data: {
        email,
        passwordHash: hash,
      },
    });
  }

  findByEmail(email: string) {
    return this.prisma.user.findUnique({ where: { email } });
  }

  findById(id: number) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  async updateRefreshToken(
    id: number,
    refreshTokenHash: string,
    refreshTokenJti: string,
  ) {
    return this.prisma.user.update({
      where: { id },
      data: {
        refreshTokenHash,
        refreshTokenJti,
      },
    });
  }

  async setGoogleData(userId: number, providerId: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { provider: "google", providerId },
    });
  }

  async setGithubData(userId: number, providerId: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: { provider: "github", providerId },
    });
  }

  findAll() {
    return this.prisma.user.findMany();
  }

  async setPassword(id: number, passwordHash: string) {
    return this.prisma.user.update({
      where: { id },
      data: { passwordHash },
    });
  }
}
