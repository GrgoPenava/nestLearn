import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsString, MinLength } from "class-validator";

export class RegisterDto {
  @ApiProperty({
    description: "Email of the user",
    example: "test@test.com",
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: "Password of the user",
    example: "password",
  })
  @IsString()
  @MinLength(6)
  password: string;
}
