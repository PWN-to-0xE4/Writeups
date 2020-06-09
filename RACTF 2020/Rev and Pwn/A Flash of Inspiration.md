# A Flash of Inspiration

### Writeup by dvoak, 300 points

`You'd never believe it, but we found a *second* guy on the desk. It looks to be the same type as the other one though, so no need to retool!`

Apparently the correct solve method was along the lines of static analysis with a binary diff to figure out the text although that route seemed complex.

I opted instead to find out how to simulate the dump instead, which is much easier. AVRSIM is a tool that can be used to simulate various AVR chips, with options to take relevant flash / eeprom dumps.

## 1: Convert .bin file to a .ihex file for parsing with avrsim

	avr-objcopy -I binary -O ihex flash.bin flash.hex

## 2: Figure out how to simulate

This step was slightly guessy for what combination of frequency and mcu options would bring success, luckily from searching around didnt take long to find some trusty 2014 forum with an examplar comamnd line for what I needed, which happened to work.

	simavr -t -m atmega328 -f 8000000 newflash.hex 


## Flag: ractf{DidYouDoAnalysis?}
