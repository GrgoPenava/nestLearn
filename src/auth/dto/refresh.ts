import { ApiProperty } from "@nestjs/swagger";
import { IsNumber, IsString } from "class-validator";

export class RefreshDto {
  @ApiProperty({
    description: "User ID",
    example: 1,
  })
  @IsNumber()
  userId: number;

  @ApiProperty({
    description: "Refresh token",
    example: "refreshToken",
  })
  @IsString()
  refreshToken: string;
}
