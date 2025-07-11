import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsString } from "class-validator";

export class LoginDto {
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
  password: string;
}
