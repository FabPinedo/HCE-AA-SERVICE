import { Module } from '@nestjs/common';
import { KafkaLoggerService } from './kafka-logger.service';

@Module({
  providers: [KafkaLoggerService],
  exports:   [KafkaLoggerService],
})
export class KafkaLoggerModule {}
