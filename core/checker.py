import copy
from fuzzywuzzy import fuzz
import re
from urllib.parse import unquote

from core.config import xsschecker
from core.requester import requester
from core.utils import replaceValue, fillHoles


def checker(url, params, headers, GET, delay, payload, positions, timeout, encoding):
    checkString = 'st4r7s' + payload + '3nd'
    if encoding:
        checkString = encoding(unquote(checkString))
    response = requester(url, replaceValue(
        params, xsschecker, checkString, copy.deepcopy), headers, GET, delay, timeout).text.lower()
    reflectedPositions = []
    for match in re.finditer('st4r7s', response):
        reflectedPositions.append(match.start())
    filledPositions = fillHoles(positions, reflectedPositions)
    #  Itretating over the reflections
    num = 0
    efficiencies = []
    checkStringLower = checkString.lower()
    for position in filledPositions:
        allEfficiencies = []
        try:
            reflected = response[reflectedPositions[num]
                :reflectedPositions[num]+len(checkString)]
            efficiency = fuzz.partial_ratio(reflected, checkStringLower)
            allEfficiencies.append(efficiency)
        except IndexError:
            pass
        if position:
            reflected = response[position:position+len(checkString)]
            efficiency = fuzz.partial_ratio(reflected, checkStringLower)
            if reflected[:-2] == ('\\%s' % checkStringLower.replace('st4r7s', '').replace('3nd', '')):
                efficiency = 90
            allEfficiencies.append(efficiency)
            efficiencies.append(max(allEfficiencies))
        else:
            efficiencies.append(0)
        num += 1
    return list(filter(None, efficiencies))
