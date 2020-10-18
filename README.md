# delaporter
[![Build Status](https://travis-ci.org/thanasisk/delaporter.svg?branch=master)](https://travis-ci.org/thanasisk/delaporter)

## Intro
This is an SSH private key password recovery tool. Have an SSH private key and
forgot the password? Have no worries, *the tool formerly known as delaporter* is here.

## Usage
*-keyfile* the keyfile you want to recover the password for

*-wordlist* the wordlist you want to use - please keep in mind that it is used *as-is*

*-type* the type of private key you want to crack - currently only rsa/dsa/ecdsa are supported

*-factor* performance factor, please see section below

*-cpuprofile* writes cpu profile to file - this is useful during development but kills performance

## Performance factor
This version introduces factor an integer variable (default value is 512).
This directly influences the number of consumers using the formula factor * number of cores.

In my 8-core machine, using a factor value of 512, saw 8 out of 8 cores being utilized.
Higher values are expected to saturate the CPU, lower values are supposed to starve it.
Feel free to experiment with this variable, as I do not have access to a lot of machines.
(hm, perhaps a blog post is a good idea?)

## Feedback
Feedback welcome at athanasios@akostopoulos.com. I also more than welcome issues/PRs
