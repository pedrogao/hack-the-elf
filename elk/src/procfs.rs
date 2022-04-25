use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    combinator::{all_consuming, map, opt, value},
    error::ParseError,
    multi::many0,
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult, InputTakeAtPosition,
};
use std::fmt;

fn is_hex_digit(c: char) -> bool {
    "0123456789abcdef".contains(c)
}

fn whitespace<I, E>(i: I) -> IResult<I, I, E>
where
    I: InputTakeAtPosition<Item = char>,
    E: ParseError<I>,
{
    take_while(|c| " \t".contains(c))(i)
}

fn spaced<I, O, E>(f: impl Fn(I) -> IResult<I, O, E>) -> impl Fn(I) -> IResult<I, O, E>
where
    I: InputTakeAtPosition<Item = char> + Clone + PartialEq,
    E: ParseError<I>,
{
    preceded(whitespace, terminated(f, whitespace))
}

fn hex_addr(i: &str) -> IResult<&str, delf::Addr> {
    let (i, num) = take_while1(is_hex_digit)(i)?;
    let u = u64::from_str_radix(num, 16).expect("our hex parser is wrong");
    Ok((i, u.into()))
}

fn hex_addr_range(i: &str) -> IResult<&str, std::ops::Range<delf::Addr>> {
    let (i, (start, end)) = separated_pair(hex_addr, tag("-"), hex_addr)(i)?;
    Ok((i, start..end))
}

pub struct Perms {
    pub r: bool,
    pub w: bool,
    pub x: bool,
    pub p: bool,
}

impl fmt::Debug for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bit = |val, display| {
            if val {
                display
            } else {
                "-"
            }
        };
        write!(
            f,
            "{}{}{}{}",
            bit(self.r, "r"),
            bit(self.w, "w"),
            bit(self.x, "x"),
            bit(self.p, "p"),
        )
    }
}

fn perms(i: &str) -> IResult<&str, Perms> {
    fn bit(c: &'static str) -> impl Fn(&str) -> IResult<&str, bool> {
        move |i: &str| -> IResult<&str, bool> {
            alt((value(false, tag("-")), value(true, tag(c))))(i)
        }
    }
    let (i, (r, w, x, p)) = tuple((bit("r"), bit("w"), bit("x"), bit("p")))(i)?;
    Ok((i, Perms { r, w, x, p }))
}

fn dec_number(i: &str) -> IResult<&str, u64> {
    let (i, s) = take_while1(|c| "0123456789".contains(c))(i)?;
    let num: u64 = s.parse().expect("our decimal parser is wrong");
    Ok((i, num))
}

pub struct Dev {
    pub major: u64,
    pub minor: u64,
}

impl fmt::Debug for Dev {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

fn dev(i: &str) -> IResult<&str, Dev> {
    let (i, (major, minor)) = separated_pair(dec_number, tag(":"), dec_number)(i)?;
    Ok((i, Dev { major, minor }))
}

#[derive(Debug)]
pub enum Source<'a> {
    Anonymous,
    Special(&'a str),
    File(&'a str),
}

impl<'a> Source<'_> {
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

fn source(i: &str) -> IResult<&str, Source<'_>> {
    fn is_path_character(c: char) -> bool {
        c != ']' && !c.is_whitespace()
    }

    fn path(i: &str) -> IResult<&str, &str> {
        take_while(is_path_character)(i)
    }

    alt((
        map(delimited(tag("["), path, tag("]")), Source::Special),
        map(path, |s| {
            if s.is_empty() {
                Source::Anonymous
            } else {
                Source::File(s)
            }
        }),
    ))(i)
}

#[derive(Debug)]
pub struct Mapping<'a> {
    pub addr_range: std::ops::Range<delf::Addr>,
    pub perms: Perms,
    pub offset: delf::Addr,
    pub dev: Dev,
    pub len: u64,
    pub source: Source<'a>,
    pub deleted: bool,
}

fn mapping(i: &str) -> IResult<&str, Mapping> {
    let (i, (addr_range, perms, offset, dev, len, source, deleted)) = tuple((
        spaced(hex_addr_range),
        spaced(perms),
        spaced(hex_addr),
        spaced(dev),
        spaced(dec_number),
        spaced(source),
        spaced(map(opt(tag("(deleted)")), |o| o.is_some())),
    ))(i)?;
    let res = Mapping {
        addr_range,
        perms,
        offset,
        dev,
        len,
        source,
        deleted,
    };
    Ok((i, res))
}

pub fn mappings(i: &str) -> IResult<&str, Vec<Mapping>> {
    all_consuming(many0(terminated(spaced(mapping), tag("\n"))))(i)
}
