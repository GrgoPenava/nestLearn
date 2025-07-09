import { ApiProperty } from "@nestjs/swagger";
import { IsString, IsNumber, IsNotEmpty } from "class-validator";

export class CreateProductDto {
  @ApiProperty({
    description: "Name of the product",
    example: "Product 1",
  })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({
    description: "Price of the product",
    example: 100,
  })
  @IsNumber()
  price: number;
}
