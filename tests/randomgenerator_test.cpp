/*
 * SPDX-FileCopyrightText: 2024 Marek Küthe <m.k@mk16.de>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <gtest/gtest.h>
#include "randomgenerator.hpp"

TEST(RandomGeneration, Generate)
{
    RandomGenerator gen(10);
    EXPECT_LE(gen.generate(), 10);
}
