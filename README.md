# delaporter
[![Build Status](https://travis-ci.org/thanasisk/delaporter.svg?branch=master)](https://travis-ci.org/thanasisk/delaporter)

This is a rudimentary SSH private key password recovery tool. It does not claim
to be production quality, as the initial coding was done in a few hours. However,
PRs/issues are more than welcome.

This version introduces factor an integer variable (default value is 1).
This directly influences the number of consumers (erroneously set initially to
the number of cores per machine) using the formula factor * number of cores.
In my 8-core machine, using a factor value of 512, saw 7 out of 8 cores being utilized.
Feel free to experiment with this variable, as I do not have access to a lot of machines.
Feedback welcome at lixtetrax@grhack.net, once I get access to more machines or
get some feedback, I will try to deduct optimal values ...
