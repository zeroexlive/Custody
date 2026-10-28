use super::wire_bytes::WireBytes;
use elliptic_curve::array::Array;
use elliptic_curve::sec1::{
    CompressedPointSize, Coordinates, FromSec1Point, Sec1Point, Tag, ToSec1Point,
};
use elliptic_curve::{CurveArithmetic, FieldBytesSize};
use generic_ec_core::coords::{HasAffineX, HasAffineXAndParity, HasAffineXY, HasAffineY, Parity};

use super::{RustCryptoCurve, RustCryptoPoint};

impl<C, X> HasAffineX for RustCryptoCurve<C, X>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    C::AffinePoint: ToSec1Point<C> + From<C::ProjectivePoint>,
    RustCryptoCurve<C, X>: generic_ec_core::Curve<
        Point = RustCryptoPoint<C>,
        CoordinateArray = WireBytes<elliptic_curve::FieldBytes<C>>,
    >,
{
    fn x(point: &Self::Point) -> Option<Self::CoordinateArray> {
        match C::AffinePoint::from(point.0)
            .to_sec1_point(false)
            .coordinates()
        {
            Coordinates::Identity => None,
            Coordinates::Uncompressed { x, .. } => Some(WireBytes(x.clone())),
            Coordinates::Compact { .. } | Coordinates::Compressed { .. } => {
                unreachable!("point was encoded in uncompressed form")
            }
        }
    }
}

impl<C, X> HasAffineXAndParity for RustCryptoCurve<C, X>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    C::AffinePoint:
        ToSec1Point<C> + FromSec1Point<C> + From<C::ProjectivePoint> + Into<C::ProjectivePoint>,
    RustCryptoCurve<C, X>: generic_ec_core::Curve<
        Point = RustCryptoPoint<C>,
        CoordinateArray = WireBytes<elliptic_curve::FieldBytes<C>>,
    >,
{
    fn x_and_parity(point: &Self::Point) -> Option<(Self::CoordinateArray, Parity)> {
        match C::AffinePoint::from(point.0)
            .to_sec1_point(true)
            .coordinates()
        {
            Coordinates::Identity => None,
            Coordinates::Compressed { x, y_is_odd } => Some((
                WireBytes(x.clone()),
                if y_is_odd { Parity::Odd } else { Parity::Even },
            )),
            Coordinates::Compact { .. } | Coordinates::Uncompressed { .. } => {
                unreachable!("point was encoded in uncompressed form")
            }
        }
    }

    fn from_x_and_parity(x: &Self::CoordinateArray, y_parity: Parity) -> Option<Self::Point> {
        let mut encoding = Array::<u8, CompressedPointSize<C>>::default();
        let tag = match y_parity {
            Parity::Even => Tag::CompressedEvenY,
            Parity::Odd => Tag::CompressedOddY,
        };
        encoding[0] = tag as u8;
        encoding[1..].copy_from_slice(x);

        let sec1_point = Sec1Point::<C>::from_bytes(&encoding).ok()?;
        C::AffinePoint::from_sec1_point(&sec1_point)
            .into_option()
            .map(|point: C::AffinePoint| RustCryptoPoint(point.into()))
    }
}

impl<C, X> HasAffineY for RustCryptoCurve<C, X>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    C::AffinePoint: ToSec1Point<C> + From<C::ProjectivePoint>,
    RustCryptoCurve<C, X>: generic_ec_core::Curve<
        Point = RustCryptoPoint<C>,
        CoordinateArray = WireBytes<elliptic_curve::FieldBytes<C>>,
    >,
{
    fn y(point: &Self::Point) -> Option<Self::CoordinateArray> {
        match C::AffinePoint::from(point.0)
            .to_sec1_point(false)
            .coordinates()
        {
            Coordinates::Identity => None,
            Coordinates::Uncompressed { y, .. } => Some(WireBytes(y.clone())),
            Coordinates::Compact { .. } | Coordinates::Compressed { .. } => {
                unreachable!("point was encoded in uncompressed form")
            }
        }
    }
}

impl<C, X> HasAffineXY for RustCryptoCurve<C, X>
where
    C: CurveArithmetic,
    FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    C::AffinePoint:
        ToSec1Point<C> + FromSec1Point<C> + From<C::ProjectivePoint> + Into<C::ProjectivePoint>,
    RustCryptoCurve<C, X>: generic_ec_core::Curve<
        Point = RustCryptoPoint<C>,
        CoordinateArray = WireBytes<elliptic_curve::FieldBytes<C>>,
    >,
{
    fn x_and_y(point: &Self::Point) -> Option<(Self::CoordinateArray, Self::CoordinateArray)> {
        match C::AffinePoint::from(point.0)
            .to_sec1_point(false)
            .coordinates()
        {
            Coordinates::Identity => None,
            Coordinates::Uncompressed { x, y } => {
                Some((WireBytes(x.clone()), WireBytes(y.clone())))
            }
            Coordinates::Compact { .. } | Coordinates::Compressed { .. } => {
                unreachable!("point was encoded in uncompressed form")
            }
        }
    }

    fn from_x_and_y(x: &Self::CoordinateArray, y: &Self::CoordinateArray) -> Option<Self::Point> {
        let sec1_point = Sec1Point::<C>::from_affine_coordinates(&x.0, &y.0, false);
        C::AffinePoint::from_sec1_point(&sec1_point)
            .into_option()
            .map(|point: C::AffinePoint| RustCryptoPoint(point.into()))
    }
}
