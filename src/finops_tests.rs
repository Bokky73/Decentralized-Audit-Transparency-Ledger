#[cfg(test)]
mod tests {
    use crate::finops::*;
    use crate::rbac::{RbacStorageKey, Role};
    use soroban_sdk::{bytes, vec, Address, Bytes, BytesN, Env, Symbol};

    fn create_test_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env
    }

    /// Grant an Admin role directly (mocked auth covers signature checks;
    /// the RBAC role check reads storage).
    fn grant_role(env: &Env, caller: &Address) {
        env.storage()
            .persistent()
            .set(&RbacStorageKey::Role(caller.clone()), &Role::Admin);
    }

    fn sample_name(env: &Env) -> Bytes {
        bytes!(env, b"TestCostCenter")
    }

    fn sample_period(env: &Env) -> Bytes {
        bytes!(env, b"2025-01")
    }

    fn sample_team(env: &Env) -> Bytes {
        bytes!(env, b"platform-team")
    }

    fn sample_region(env: &Env) -> Bytes {
        bytes!(env, b"us-east-1")
    }

    // ── Cost Center Tests ──────────────────────────────────────────────

    #[test]
    fn test_register_cost_center() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let id = register_cost_center(
            env.clone(),
            caller,
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        assert!(!id.to_vec().is_empty());

        let center = get_cost_center(env.clone(), id);
        assert_eq!(center.budget, 100000);
        assert_eq!(center.currency, Symbol::new(&env, "USD"));
        assert!(center.active);
    }

    #[test]
    fn test_duplicate_cost_center_fails() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            register_cost_center(
                env,
                caller,
                sample_name(&env),
                200000,
                Symbol::new(&env, "USD"),
            );
        }));
        assert!(result.is_err());
    }

    #[test]
    fn test_update_cost_center_budget() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        update_cost_center_budget(env.clone(), caller, id, 200000);

        let center = get_cost_center(env, id);
        assert_eq!(center.budget, 200000);
    }

    #[test]
    fn test_deactivate_cost_center() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        deactivate_cost_center(env.clone(), caller, id);

        let center = get_cost_center(env, id);
        assert!(!center.active);
    }

    // ── Cost Allocation Tests ──────────────────────────────────────────

    #[test]
    fn test_allocate_cost() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let alloc_id = allocate_cost(
            env.clone(),
            caller,
            cc_id,
            Symbol::new(&env, "compute"),
            5000,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            bytes!(env, b"monthly-compute"),
        );

        assert!(!alloc_id.to_vec().is_empty());

        let alloc = get_allocation(env, alloc_id);
        assert_eq!(alloc.amount, 5000);
        assert_eq!(alloc.resource_type, Symbol::new(&env, "compute"));
    }

    // ── Chargeback / Showback Tests ────────────────────────────────────

    #[test]
    fn test_create_chargeback() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let cb_id = create_chargeback(
            env.clone(),
            caller,
            sample_team(&env),
            2500,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            cc_id,
        );

        assert!(!cb_id.to_vec().is_empty());
    }

    #[test]
    fn test_create_showback() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let sb_id = create_showback(
            env.clone(),
            caller,
            sample_team(&env),
            2500,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            cc_id,
        );

        assert!(!sb_id.to_vec().is_empty());
    }

    #[test]
    fn test_approve_chargeback() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let cb_id = create_chargeback(
            env.clone(),
            caller,
            sample_team(&env),
            2500,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            cc_id,
        );

        approve_chargeback(env.clone(), caller, cb_id);

        let key = DataKey::Chargeback(cb_id);
        if let Some(record) = env.storage().persistent().get::<_, ChargebackRecord>(&key) {
            assert_eq!(record.status, 2);
        }
    }

    // ── Rightsizing Tests ──────────────────────────────────────────────

    #[test]
    fn test_record_resource() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let resource_id = record_resource(
            env.clone(),
            caller,
            Symbol::new(&env, "ec2"),
            8,
            800,
            sample_region(&env),
        );

        assert!(!resource_id.to_vec().is_empty());

        let resource = env
            .storage()
            .persistent()
            .get(&DataKey::Resource(resource_id))
            .unwrap();
        assert_eq!(resource.current_size, 8);
        assert_eq!(resource.monthly_cost, 800);
    }

    #[test]
    fn test_generate_rightsizing() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let resource_id = record_resource(
            env.clone(),
            caller.clone(),
            Symbol::new(&env, "ec2"),
            8,
            800,
            sample_region(&env),
        );

        let rec_id = generate_rightsizing(env.clone(), caller, resource_id);

        let rec = get_rightsizing(env, rec_id);
        assert_eq!(rec.current_size, 8);
        assert_eq!(rec.recommended_size, 4);
        assert_eq!(rec.monthly_savings, 400);
        assert_eq!(rec.confidence, 75);
    }

    // ── Anomaly Detection Tests ────────────────────────────────────────

    #[test]
    fn test_record_anomaly() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let resource_id = BytesN::from_slice(&env, b"resource-anomaly-test");
        let anomaly_id = record_anomaly(
            env.clone(),
            caller,
            resource_id,
            1000,
            1500,
            bytes!(env, b"spike-due-to-outage"),
        );

        assert!(!anomaly_id.to_vec().is_empty());

        let anomaly = env
            .storage()
            .persistent()
            .get(&DataKey::CostAnomaly(anomaly_id))
            .unwrap();
        assert_eq!(anomaly.actual_cost, 1500);
        assert_eq!(anomaly.expected_cost, 1000);
        assert!(!anomaly.resolved);
    }

    #[test]
    fn test_detect_anomalies() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let resource_id = BytesN::from_slice(&env, b"resource-anomaly-test-2");
        record_anomaly(
            env.clone(),
            caller.clone(),
            resource_id.clone(),
            1000,
            2000,
            bytes!(env, b"high-deviation"),
        );

        let anomalies = detect_anomalies(env, caller, resource_id);
        assert_eq!(anomalies.len(), 1);
    }

    #[test]
    fn test_resolve_anomaly() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let resource_id = BytesN::from_slice(&env, b"resource-anomaly-test-3");
        let anomaly_id = record_anomaly(
            env.clone(),
            caller.clone(),
            resource_id,
            1000,
            1500,
            bytes!(env, b"resolve-test"),
        );

        resolve_anomaly(env.clone(), caller, anomaly_id.clone());

        let anomaly = env
            .storage()
            .persistent()
            .get(&DataKey::CostAnomaly(anomaly_id))
            .unwrap();
        assert!(anomaly.resolved);
    }

    // ── Budget Tests ───────────────────────────────────────────────────

    #[test]
    fn test_create_budget() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let thresholds = vec![&env, 50, 80, 95];
        let budget_id = create_budget(
            env.clone(),
            caller,
            bytes!(env, b"monthly-budget"),
            cc_id,
            50000,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            thresholds,
        );

        assert!(!budget_id.to_vec().is_empty());

        let budget = get_budget(env, budget_id);
        assert_eq!(budget.amount, 50000);
        assert!(budget.active);
    }

    #[test]
    fn test_check_budget_alert() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        let thresholds = vec![&env, 50, 80];
        let budget_id = create_budget(
            env.clone(),
            caller.clone(),
            bytes!(env, b"monthly-budget"),
            cc_id,
            100000,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            thresholds,
        );

        let alert_id = check_budget(env.clone(), caller, budget_id, 85000);
        assert!(!alert_id.to_vec().is_empty());
    }

    // ── Dashboard Tests ────────────────────────────────────────────────

    #[test]
    fn test_generate_dashboard() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        allocate_cost(
            env.clone(),
            caller.clone(),
            cc_id,
            Symbol::new(&env, "compute"),
            5000,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            bytes!(env, b"monthly-compute"),
        );

        record_resource(
            env.clone(),
            caller,
            Symbol::new(&env, "ec2"),
            8,
            800,
            sample_region(&env),
        );

        let dashboard = generate_dashboard(env);
        assert!(dashboard.timestamp > 0);
    }

    #[test]
    fn test_get_cost_summary() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        allocate_cost(
            env,
            caller,
            cc_id,
            Symbol::new(&env, "compute"),
            5000,
            Symbol::new(&env, "USD"),
            sample_period(&env),
            bytes!(env, b"monthly-compute"),
        );

        let summary = get_cost_summary(env, sample_period(&env));
        assert_eq!(summary.total_cost, 5000);
    }

    // ── Query Helper Tests ─────────────────────────────────────────────

    #[test]
    fn test_cost_center_count() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        assert_eq!(get_cost_center_count(env.clone()), 0);

        register_cost_center(
            env.clone(),
            caller,
            sample_name(&env),
            100000,
            Symbol::new(&env, "USD"),
        );

        assert_eq!(get_cost_center_count(env), 1);
    }

    #[test]
    fn test_active_anomaly_count() {
        let env = create_test_env();
        let caller = Address::random(&env);
        grant_role(&env, &caller);

        assert_eq!(get_active_anomaly_count(env.clone()), 0);

        let resource_id = BytesN::from_slice(&env, b"resource-anomaly-count");
        record_anomaly(
            env.clone(),
            caller,
            resource_id,
            1000,
            1500,
            bytes!(env, b"count-test"),
        );

        assert_eq!(get_active_anomaly_count(env), 1);
    }

    // ── Pagination Edge-Case Tests ─────────────────────────────────────

    fn seed_allocations(env: &Env, caller: &Address, count: u32) -> BytesN<32> {
        let cc_id = register_cost_center(
            env.clone(),
            caller.clone(),
            sample_name(env),
            1_000_000,
            Symbol::new(env, "USD"),
        );

        for i in 0..count {
            allocate_cost(
                env.clone(),
                caller.clone(),
                cc_id.clone(),
                Symbol::new(env, "compute"),
                100 + i as i128,
                Symbol::new(env, "USD"),
                sample_period(env),
                bytes!(env, b"pagination-seed"),
            );
        }

        cc_id
    }

    #[test]
    fn test_page_limit_cap_enforced() {
        // The page limit cap must be 100; anything above is rejected or clamped.
        assert_eq!(MAX_PAGE_LIMIT, 100);

        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 3);

        let query = AllocationQuery {
            cursor: None,
            limit: 500,
            filter: QueryFilter::default(),
        };

        let page = query_allocations(env.clone(), query);
        assert!(page.items.len() <= MAX_PAGE_LIMIT);
    }

    #[test]
    fn test_empty_result_set() {
        let env = create_test_env();

        let query = AllocationQuery {
            cursor: None,
            limit: 10,
            filter: QueryFilter::default(),
        };

        let page = query_allocations(env, query);
        assert_eq!(page.items.len(), 0);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn test_single_item_page() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 5);

        let query = AllocationQuery {
            cursor: None,
            limit: 1,
            filter: QueryFilter::default(),
        };

        let page = query_allocations(env.clone(), query);
        assert_eq!(page.items.len(), 1);
        assert!(page.next_cursor.is_some());

        // Second single-item page must not repeat the first item.
        let query2 = AllocationQuery {
            cursor: page.next_cursor.clone(),
            limit: 1,
            filter: QueryFilter::default(),
        };
        let page2 = query_allocations(env, query2);
        assert_eq!(page2.items.len(), 1);
        assert_ne!(page.items.get(0).unwrap().id, page2.items.get(0).unwrap().id);
    }

    #[test]
    fn test_cursor_past_end_returns_empty_page() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 3);

        // Walk to the end to obtain a terminal cursor.
        let mut cursor: Option<PageCursor> = None;
        loop {
            let query = AllocationQuery {
                cursor: cursor.clone(),
                limit: 2,
                filter: QueryFilter::default(),
            };
            let page = query_allocations(env.clone(), query);
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        // A cursor past the end must yield an empty page with no next_cursor.
        let query = AllocationQuery {
            cursor,
            limit: 2,
            filter: QueryFilter::default(),
        };
        let page = query_allocations(env, query);
        assert_eq!(page.items.len(), 0);
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn test_full_multi_page_traversal_reconstructs_collection() {
        let env = create_test_env();
        let caller = Address::random(&env);
        let total = 25u32;
        seed_allocations(&env, &caller, total);

        let mut seen: Vec<BytesN<32>> = Vec::new();
        let mut cursor: Option<PageCursor> = None;

        loop {
            let query = AllocationQuery {
                cursor: cursor.clone(),
                limit: 7,
                filter: QueryFilter::default(),
            };
            let page = query_allocations(env.clone(), query);

            for item in page.items.iter() {
                seen.push(item.id.clone());
            }

            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        assert_eq!(seen.len() as u32, total);

        // No duplicates across pages.
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), seen.len());
    }

    #[test]
    fn test_filter_by_timestamp_range() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 5);

        let filter = QueryFilter {
            from_timestamp: Some(0),
            to_timestamp: Some(u64::MAX),
            status: None,
            submitter: None,
        };

        let query = AllocationQuery {
            cursor: None,
            limit: 100,
            filter,
        };
        let page = query_allocations(env.clone(), query);
        assert_eq!(page.items.len(), 5);

        // A range that excludes everything.
        let filter_none = QueryFilter {
            from_timestamp: Some(u64::MAX - 1),
            to_timestamp: Some(u64::MAX),
            status: None,
            submitter: None,
        };
        let query_none = AllocationQuery {
            cursor: None,
            limit: 100,
            filter: filter_none,
        };
        let page_none = query_allocations(env, query_none);
        assert_eq!(page_none.items.len(), 0);
    }

    #[test]
    fn test_filter_by_status_enum() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 4);

        let filter = QueryFilter {
            from_timestamp: None,
            to_timestamp: None,
            status: Some(AllocationStatus::Active),
            submitter: None,
        };
        let query = AllocationQuery {
            cursor: None,
            limit: 100,
            filter,
        };
        let page = query_allocations(env.clone(), query);
        assert_eq!(page.items.len(), 4);

        let filter_other = QueryFilter {
            from_timestamp: None,
            to_timestamp: None,
            status: Some(AllocationStatus::Archived),
            submitter: None,
        };
        let query_other = AllocationQuery {
            cursor: None,
            limit: 100,
            filter: filter_other,
        };
        let page_other = query_allocations(env, query_other);
        assert_eq!(page_other.items.len(), 0);
    }

    #[test]
    fn test_filter_by_submitter_address() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 3);

        let filter = QueryFilter {
            from_timestamp: None,
            to_timestamp: None,
            status: None,
            submitter: Some(caller.clone()),
        };
        let query = AllocationQuery {
            cursor: None,
            limit: 100,
            filter,
        };
        let page = query_allocations(env.clone(), query);
        assert_eq!(page.items.len(), 3);

        let other = Address::random(&env);
        let filter_other = QueryFilter {
            from_timestamp: None,
            to_timestamp: None,
            status: None,
            submitter: Some(other),
        };
        let query_other = AllocationQuery {
            cursor: None,
            limit: 100,
            filter: filter_other,
        };
        let page_other = query_allocations(env, query_other);
        assert_eq!(page_other.items.len(), 0);
    }

    #[test]
    fn test_combined_filters() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 6);

        let filter = QueryFilter {
            from_timestamp: Some(0),
            to_timestamp: Some(u64::MAX),
            status: Some(AllocationStatus::Active),
            submitter: Some(caller.clone()),
        };
        let query = AllocationQuery {
            cursor: None,
            limit: 100,
            filter,
        };
        let page = query_allocations(env.clone(), query);
        assert_eq!(page.items.len(), 6);

        // Combining an impossible predicate yields nothing.
        let filter_impossible = QueryFilter {
            from_timestamp: Some(0),
            to_timestamp: Some(u64::MAX),
            status: Some(AllocationStatus::Active),
            submitter: Some(Address::random(&env)),
        };
        let query_impossible = AllocationQuery {
            cursor: None,
            limit: 100,
            filter: filter_impossible,
        };
        let page_impossible = query_allocations(env, query_impossible);
        assert_eq!(page_impossible.items.len(), 0);
    }

    #[test]
    fn test_deterministic_ordering_stable_across_queries() {
        let env = create_test_env();
        let caller = Address::random(&env);
        seed_allocations(&env, &caller, 10);

        let query = AllocationQuery {
            cursor: None,
            limit: 100,
            filter: QueryFilter::default(),
        };

        let first = query_allocations(env.clone(), query.clone());
        let second = query_allocations(env.clone(), query.clone());
        let third = query_allocations(env, query);

        let ids_first: Vec<BytesN<32>> = first.items.iter().map(|i| i.id.clone()).collect();
        let ids_second: Vec<BytesN<32>> = second.items.iter().map(|i| i.id.clone()).collect();
        let ids_third: Vec<BytesN<32>> = third.items.iter().map(|i| i.id.clone()).collect();

        assert_eq!(ids_first, ids_second);
        assert_eq!(ids_second, ids_third);
    }
}
