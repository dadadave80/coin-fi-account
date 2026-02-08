// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Account} from "../src/Account.sol";
import {Escrow} from "../src/Escrow.sol";
import {Orchestrator} from "../src/Orchestrator.sol";
import {SimpleFunder} from "../src/SimpleFunder.sol";
import {SimpleSettler} from "../src/SimpleSettler.sol";
import {Simulator} from "../src/Simulator.sol";
import {DiamondCutFacet} from "../src/facets/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "../src/facets/DiamondLoupeFacet.sol";
import {GetSelectors} from "../test/helper/GetSelectors.sol";
import {Script, console} from "forge-std/Script.sol";

contract DeployAll is Script, GetSelectors {
    address public orchestrator;
    address public accountImplementation;
    address public accountProxy;
    address public simulator;
    address public funder;
    address public simpleSettler;
    address public escrow;
    address public accountFacet;
    address public diamondCutFacet;
    address public diamondLoupeFacet;

    function run() external {
        vm.startBroadcast();
        diamondCutFacet = address(new DiamondCutFacet());
        diamondLoupeFacet = address(new DiamondLoupeFacet());
        accountFacet = address(new AccountFacet());
        orchestrator = address(new Orchestrator());
        accountImplementation = address(new Account(orchestrator));
        accountProxy = LibEIP7702.deployProxy(accountImplementation, address(0));
        simulator = address(new Simulator());

        funder = address(new SimpleFunder(vm.envAddress("FUNDER"), msg.sender));
        address[] memory ocs = new address[](1);
        ocs[0] = address(orchestrator);
        SimpleFunder(payable(funder)).setOrchestrators(ocs, true);
        simpleSettler = address(new SimpleSettler(vm.envAddress("SETTLER_OWNER")));
        escrow = address(new Escrow());

        vm.stopBroadcast();
    }
}
