// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::de::Error as _;
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

use super::{
    ZkProtoJsonError, MAX_JSON_CONTAINER_ELEMENTS, MAX_JSON_NESTING_DEPTH, MAX_JSON_TOTAL_VALUES,
};

struct JsonBudget {
    depth: usize,
    total_values: usize,
    exceeded: bool,
}

impl JsonBudget {
    fn enter_value<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.total_values = self.total_values.checked_add(1).ok_or_else(|| {
            self.exceeded = true;
            E::custom("json value budget exceeded")
        })?;
        if self.total_values > MAX_JSON_TOTAL_VALUES {
            self.exceeded = true;
            return Err(E::custom("json value budget exceeded"));
        }
        Ok(())
    }

    fn enter_container<E: serde::de::Error>(&mut self) -> Result<(), E> {
        self.depth = self.depth.checked_add(1).ok_or_else(|| {
            self.exceeded = true;
            E::custom("json depth budget exceeded")
        })?;
        if self.depth > MAX_JSON_NESTING_DEPTH {
            self.exceeded = true;
            return Err(E::custom("json depth budget exceeded"));
        }
        Ok(())
    }

    fn leave_container(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn require_container_count<E: serde::de::Error>(&mut self, count: usize) -> Result<(), E> {
        if count > MAX_JSON_CONTAINER_ELEMENTS {
            self.exceeded = true;
            return Err(E::custom("json container budget exceeded"));
        }
        Ok(())
    }
}

struct BudgetSeed<'a> {
    budget: &'a mut JsonBudget,
}

impl<'de> DeserializeSeed<'de> for BudgetSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        self.budget.enter_value()?;
        deserializer.deserialize_any(BudgetVisitor {
            budget: self.budget,
        })
    }
}

struct BudgetVisitor<'a> {
    budget: &'a mut JsonBudget,
}

impl<'de> Visitor<'de> for BudgetVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E: serde::de::Error>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_borrowed_str<E: serde::de::Error>(self, _value: &'de str) -> Result<(), E> {
        Ok(())
    }
    fn visit_string<E: serde::de::Error>(self, _value: String) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        BudgetSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<(), D::Error> {
        BudgetSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        self.budget.enter_container()?;
        let mut count = 0_usize;
        while sequence
            .next_element_seed(BudgetSeed {
                budget: self.budget,
            })?
            .is_some()
        {
            count = count.checked_add(1).ok_or_else(|| {
                self.budget.exceeded = true;
                A::Error::custom("json container budget exceeded")
            })?;
            self.budget.require_container_count::<A::Error>(count)?;
        }
        self.budget.leave_container();
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.budget.enter_container()?;
        let mut count = 0_usize;
        while map
            .next_key_seed(BudgetSeed {
                budget: self.budget,
            })?
            .is_some()
        {
            map.next_value_seed(BudgetSeed {
                budget: self.budget,
            })?;
            count = count.checked_add(1).ok_or_else(|| {
                self.budget.exceeded = true;
                A::Error::custom("json container budget exceeded")
            })?;
            self.budget.require_container_count::<A::Error>(count)?;
        }
        self.budget.leave_container();
        Ok(())
    }
}

pub(super) fn preflight_json_budget(json: &[u8]) -> Result<(), ZkProtoJsonError> {
    let mut budget = JsonBudget {
        depth: 0,
        total_values: 0,
        exceeded: false,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let result = BudgetSeed {
        budget: &mut budget,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());
    match result {
        Ok(()) => Ok(()),
        Err(_) if budget.exceeded => Err(ZkProtoJsonError::JsonTooLarge),
        Err(_) => Err(ZkProtoJsonError::JsonDeserialize),
    }
}
