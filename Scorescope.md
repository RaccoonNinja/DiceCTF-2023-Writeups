## Skills required: Getting on the right track, reading documentation, some PyJail escape, some guessing

We're only given an access to a web interface, we can submit `.py` files and the program will grade us based on 22 test cases.

![image](https://user-images.githubusercontent.com/114584910/216975124-3908458f-8dbe-4372-9d61-be58c8f0f21a.png)

There's a `template.py` which reveals that some challenges are really impossible (for me, it may be possible to recover the random seed given enough output):

```py
def magic():
    '''
    Guess the random number I am thinking of.

    Returns:
        int: Your guess.
    '''

    ######## YOUR CODE ########

    raise NotImplementedError

    ###########################
```

The first 21 test cases correspond to the functions in `template.py` and `test_hidden` *errors* with the output hidden.

I joined midway and teammates are discussing various ideas like leaking the `test_hidden` message, leaking info with custom errors and achieving RCE with PyJail escape,
which I know almost nothing about.
After some time I felt like we were running in circles and thought *okay, maybe I can use some noob perspective ~~and pro hint elicitation~~* and raised a ticket (I'm more open to raising tickets as the majority of CTF experience was solo):

> 🦝: Since we don't have any source, can I get clarification on the challenge scope (what we need to do)? Is leaking `test_hidden` enough or do we need reverse shell?

> 🚩: You get the flag if you pass all test cases - I'm not sure if I can help more than that

> 🦝: Nah this is good enough thx

This is what resetted our path, and the only hint I needed.

We began the research on possible libraries, and eventually focused on the [unittest module in standard library](https://docs.python.org/3/library/unittest.html).
This is a surprising discovery for me, but the more surprising thing was that we could overwrite the checking methods:
```py
# Credits to Mystiz for the very succinct code
noop = lambda *x: None

__import__('unittest').TestCase.assertEqual = noop
__import__('unittest').TestCase.assertGreater = noop

def add(a, b):
    return a + b
```

This way we can get 21/22, with *test_hidden* remaining.

I was lucky enough to deliver the final blow with something cls:
```py
@classmethod
def setUpClass(cls):
    cls.test_hidden = noop

__import__('unittest').TestCase.setUpClass=setUpClass
```

> I'm really struggling in this *class*. Care to give me a hand?
