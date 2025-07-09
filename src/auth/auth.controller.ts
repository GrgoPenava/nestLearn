import { Body, Controller, Get, Post, Req, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { AuthGuard } from "@nestjs/passport";
import { RegisterDto } from "./dto/register";
import { LoginDto } from "./dto/login";
import { RefreshDto } from "./dto/refresh";
import { ApiExcludeEndpoint, ApiOkResponse, ApiTags } from "@nestjs/swagger";

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post("register")
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email, dto.password);
  }

  @ApiOkResponse({ type: LoginDto })
  @Post("login")
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto.email, dto.password);
  }

  @Post("refresh")
  refresh(@Body() dto: RefreshDto) {
    return this.authService.refresh(dto.userId, dto.refreshToken);
  }

  @Get("google")
  @ApiExcludeEndpoint()
  @UseGuards(AuthGuard("google"))
  async googleAuth() {}

  @Get("google/callback")
  @ApiExcludeEndpoint()
  @UseGuards(AuthGuard("google"))
  googleAuthRedirect(@Req() req) {
    return req.user;
  }

  @Get("github")
  @ApiExcludeEndpoint()
  @UseGuards(AuthGuard("github"))
  async githubAuth() {}

  @Get("github/callback")
  @ApiExcludeEndpoint()
  @UseGuards(AuthGuard("github"))
  githubAuthRedirect(@Req() req) {
    return req.user;
  }
}
